#!/usr/bin/env bash
# =============================================================================
# generate_autotls_csrs_v2.sh
# Cloudera CDP Auto-TLS — Per-Node CSR & Key Generation (SSH Mode)
#
# PURPOSE:
#   SSHes into each host, generates the RSA private key and CSR locally ON
#   THAT HOST, then copies both files back to the Cloudera Manager host into
#   a per-hostname folder under /tmp/auto-tls/.
#
# REFERENCE:
#   https://docs.cloudera.com/cdp-private-cloud-base/latest/security-encrypting-data-in-transit/topics/cm-security-use-case-4.html
#
# FIPS NOTE:
#   For FIPS-enabled clusters, RSA key size MUST be 2048 or 3072.
#   RSA 4096 is not FIPS-approved. Change KEY_BITS below accordingly.
#
# PREREQUISITES:
#   - Passwordless SSH from this host to all cluster nodes
#   - openssl installed on all remote hosts
#   - Run as the user that owns the SSH key
#
# USAGE:
#   ./generate_autotls_csrs_v2.sh <hosts_file>
#
# HOSTS FILE FORMAT (pipe-delimited, one host per line):
#   fqdn|ip|extra_sans
#
#   extra_sans is optional and comma-separated:
#     cdp-master1.cloudera.test.local|10.10.10.11|
#     cdp-Cloudera Manager host.cloudera.test.local|10.10.10.12|DNS:cloudera-manager.cloudera.test.local
#
#   Blank lines and lines starting with # are ignored.
#
# OUTPUT STRUCTURE ON CM HOST:
#   /tmp/auto-tls/
#   ├── keys/
#   │   └── key.pwd
#   ├── cdp-master1.cloudera.test.local/
#   │   ├── cdp-master1.cloudera.test.local-key.pem
#   │   └── cdp-master1.cloudera.test.local.csr
#   └── ... (one folder per host, exactly 2 files each)
#
# =============================================================================
set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

CERT_C="AE"
CERT_ST="State"
CERT_L="City"
CERT_O="Example Organization"
CERT_OU="IT"

# Key size — 4096 for non-FIPS. FIPS clusters: use 2048 or 3072.
KEY_BITS=4096
DIGEST="sha256"
CERT_DAYS=365

BASE_DIR="/tmp/auto-tls"
KEY_PWD_DIR="${BASE_DIR}/keys"
KEY_PWD_FILE="${KEY_PWD_DIR}/key.pwd"
PWD_LENGTH=32

SSH_USER="cloudera"
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10"
REMOTE_TMP="/tmp/autotls-gen"

# =============================================================================
# COLOUR HELPERS
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}>>> $* ${RESET}"; }

# =============================================================================
# PREREQUISITES
# =============================================================================

check_prerequisites() {
    section "Checking local prerequisites"
    local missing=0
    for cmd in openssl ssh scp cut tr sed grep; do
        if command -v "${cmd}" &>/dev/null; then
            ok "Found: ${cmd}"
        else
            error "Required command not found: ${cmd}"
            missing=$(( missing + 1 ))
        fi
    done
    if [[ ${missing} -gt 0 ]]; then
        error "${missing} prerequisite(s) missing. Aborting."
        exit 1
    fi
    info "OpenSSL: $(openssl version)"
}

# =============================================================================
# ARGUMENT VALIDATION
# =============================================================================

validate_args() {
    if [[ $# -ne 1 ]]; then
        error "Usage: $0 <hosts_file>"
        echo ""
        echo "  Format: fqdn|ip|extra_sans"
        echo "  Example:"
        echo "    cdp-master1.cloudera.test.local|10.10.10.11|"
        echo "    cdp-Cloudera Manager host.cloudera.test.local|10.10.10.12|DNS:cloudera-manager.cloudera.test.local"
        exit 1
    fi
    HOSTS_FILE="$1"
    if [[ ! -f "${HOSTS_FILE}" ]]; then
        error "Hosts file not found: ${HOSTS_FILE}"
        exit 1
    fi
    if [[ ! -r "${HOSTS_FILE}" ]]; then
        error "Hosts file not readable: ${HOSTS_FILE}"
        exit 1
    fi
}

# =============================================================================
# KEY PASSWORD
# =============================================================================

setup_key_password() {
    section "Setting up shared key password (on CM host)"
    mkdir -p "${KEY_PWD_DIR}"
    chmod 700 "${KEY_PWD_DIR}"

    if [[ -f "${KEY_PWD_FILE}" ]]; then
        warn "key.pwd already exists — reusing. Delete ${KEY_PWD_FILE} to regenerate."
    else
        info "Generating random passphrase (${PWD_LENGTH} chars)..."
        openssl rand -base64 48 \
            | tr -dc 'A-Za-z0-9@#%^&*()-_=+' \
            | head -c "${PWD_LENGTH}" \
            > "${KEY_PWD_FILE}"
        printf '\n' >> "${KEY_PWD_FILE}"
        chmod 600 "${KEY_PWD_FILE}"
        ok "Passphrase written to: ${KEY_PWD_FILE}"
    fi
}

# =============================================================================
# PARSE HOST LINE
# Populates globals: PARSED_FQDN, PARSED_IP, PARSED_EXTRA
# =============================================================================

parse_host_line() {
    local raw_line="$1"
    PARSED_FQDN=$(echo "${raw_line}" | cut -d'|' -f1 | tr -d '[:space:]')
    PARSED_IP=$(  echo "${raw_line}" | cut -d'|' -f2 | tr -d '[:space:]')
    PARSED_EXTRA=$(echo "${raw_line}" | cut -d'|' -f3 | tr -d '[:space:]')

    if [[ -z "${PARSED_FQDN}" ]]; then
        error "Empty FQDN in line: ${raw_line}"
        return 1
    fi
    if [[ -z "${PARSED_IP}" ]]; then
        error "Empty IP for host '${PARSED_FQDN}'"
        return 1
    fi
    if ! echo "${PARSED_FQDN}" | \
         grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        error "Invalid FQDN: ${PARSED_FQDN}"
        return 1
    fi
    if ! echo "${PARSED_IP}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        error "Invalid IP: ${PARSED_IP} (host: ${PARSED_FQDN})"
        return 1
    fi
    return 0
}


# =============================================================================
# SSH TEST
# =============================================================================

test_ssh() {
    local host="$1"
    if ssh ${SSH_OPTS} "${SSH_USER}@${host}" "echo ssh-ok" &>/dev/null; then
        return 0
    fi
    return 1
}

# =============================================================================
# BUILD REMOTE SCRIPT — all values pre-substituted locally, no variable
# quoting issues crossing the SSH boundary.
# =============================================================================

build_remote_script() {
    local fqdn="$1"
    local san_string="$2"
    local subject="$3"
    local tmpfile
    tmpfile=$(mktemp /tmp/autotls-remote-XXXXXX.sh)

    cat > "${tmpfile}" << REMOTE_EOF
#!/usr/bin/env bash
set -euo pipefail

REMOTE_TMP="${REMOTE_TMP}"
REMOTE_KEY="${REMOTE_TMP}/${fqdn}-key.pem"
REMOTE_CSR="${REMOTE_TMP}/${fqdn}.csr"
REMOTE_PWD="${REMOTE_TMP}/key.pwd"

openssl req \\
    -newkey    "rsa:${KEY_BITS}" \\
    -${DIGEST} \\
    -days      "${CERT_DAYS}" \\
    -keyout    "\${REMOTE_KEY}" \\
    -out       "\${REMOTE_CSR}" \\
    -passout   "file:\${REMOTE_PWD}" \\
    -subj      "${subject}" \\
    -reqexts san \\
    -config <( printf '[req]\ndistinguished_name=req\nreq_extensions=san\n[san]\nsubjectAltName=${san_string}\nextendedKeyUsage=serverAuth,clientAuth\n' ) \\
    2>/dev/null

chmod 600 "\${REMOTE_KEY}"
chmod 644 "\${REMOTE_CSR}"
echo "DONE"
REMOTE_EOF

    chmod 600 "${tmpfile}"
    echo "${tmpfile}"
}

# =============================================================================
# PER-HOST PROCESSING
# =============================================================================

FAILED_HOSTS=()

generate_for_host() {
    local fqdn="$1"
    local ip="$2"
    local extra_sans="$3"

    local host_dir="${BASE_DIR}/${fqdn}"
    local local_key="${host_dir}/${fqdn}-key.pem"
    local local_csr="${host_dir}/${fqdn}.csr"
    local remote_key="${REMOTE_TMP}/${fqdn}-key.pem"
    local remote_csr="${REMOTE_TMP}/${fqdn}.csr"
    local remote_script_path="${REMOTE_TMP}/gen.sh"

    local short_name
    short_name=$(echo "${fqdn}" | cut -d'.' -f1)

    section "Processing: ${fqdn}"
    info "  IP          : ${ip}"
    info "  Short name  : ${short_name}"
    info "  Extra SANs  : ${extra_sans:-<none>}"

    # Skip if already collected
    if [[ -f "${local_key}" ]] && [[ -f "${local_csr}" ]]; then
        warn "Already collected for ${fqdn} — skipping. Remove ${host_dir}/ to regenerate."
        return 0
    fi

    # SSH connectivity check
    info "  Testing SSH connectivity..."
    if ! test_ssh "${fqdn}"; then
        error "Cannot SSH to ${fqdn} as ${SSH_USER} — skipping."
        error "  Check: ssh ${SSH_USER}@${fqdn}"
        FAILED_HOSTS+=("${fqdn}")
        return 0
    fi
    ok "  SSH OK"

    # Build SAN string
    local san_string="DNS:${fqdn},DNS:${short_name},IP:${ip}"
    if [[ -n "${extra_sans}" ]]; then
        san_string="${san_string},${extra_sans}"
    fi

    # Build subject — assembled locally, never passed as a variable over SSH
    local subject="/C=${CERT_C}/ST=${CERT_ST}/L=${CERT_L}/O=${CERT_O}/OU=${CERT_OU}/CN=${fqdn}"

    info "  SANs        : ${san_string}"
    info "  Subject     : ${subject}"

 # ------------------------------------------------------------------
    # STEP 1: Prepare remote tmp dir and copy key.pwd
    # ------------------------------------------------------------------
    info "  Preparing remote host..."
    ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "mkdir -p ${REMOTE_TMP} && chmod 700 ${REMOTE_TMP}"
    scp -q ${SSH_OPTS} "${KEY_PWD_FILE}" "${SSH_USER}@${fqdn}:${REMOTE_TMP}/key.pwd"
    ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "chmod 600 ${REMOTE_TMP}/key.pwd"

    # ------------------------------------------------------------------
    # STEP 2: Build and SCP the generation script (values pre-substituted)
    # ------------------------------------------------------------------
    local local_script
    local_script=$(build_remote_script "${fqdn}" "${san_string}" "${subject}")
    scp -q ${SSH_OPTS} "${local_script}" "${SSH_USER}@${fqdn}:${remote_script_path}"
    ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "chmod 700 ${remote_script_path}"
    rm -f "${local_script}"

    # ------------------------------------------------------------------
    # STEP 3: Execute generation script on remote host
    # ------------------------------------------------------------------
    info "  Generating ${KEY_BITS}-bit RSA key + CSR on ${fqdn}..."
    local result
    result=$(ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "bash ${remote_script_path}")

    if [[ "${result}" != "DONE" ]]; then
        error "Remote generation failed on ${fqdn}. Output: ${result}"
        FAILED_HOSTS+=("${fqdn}")
        ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "rm -rf ${REMOTE_TMP}" || true
        return 0
    fi
    ok "  Key + CSR generated on ${fqdn}"

    # ------------------------------------------------------------------
    # STEP 4: Copy key and CSR back to CM host
    # ------------------------------------------------------------------
    info "  Copying files back to CM host..."
    mkdir -p "${host_dir}"
    chmod 700 "${host_dir}"
    scp -q ${SSH_OPTS} "${SSH_USER}@${fqdn}:${remote_key}" "${local_key}"
    scp -q ${SSH_OPTS} "${SSH_USER}@${fqdn}:${remote_csr}" "${local_csr}"
    chmod 600 "${local_key}"
    chmod 644 "${local_csr}"
    ok "  Key : ${local_key}"
    ok "  CSR : ${local_csr}"

    # ------------------------------------------------------------------
    # STEP 5: Clean up remote host
    # ------------------------------------------------------------------
    info "  Cleaning up remote host..."
    ssh ${SSH_OPTS} "${SSH_USER}@${fqdn}" "rm -rf ${REMOTE_TMP}"
    ok "  Remote cleanup done"

    # ------------------------------------------------------------------
    # STEP 6: Verify CSR locally
    # ------------------------------------------------------------------
    info "  Verifying CSR..."
    local csr_subject
    csr_subject=$(openssl req -in "${local_csr}" -noout -subject 2>/dev/null)
    info "    Subject : ${csr_subject}"
    local csr_san_line
    csr_san_line=$(openssl req -in "${local_csr}" -noout -text 2>/dev/null \
                  | grep -A1 'Subject Alternative Name' \
                  | tail -1 \
                  | sed 's/^[[:space:]]*//' || true)
    if [[ -n "${csr_san_line}" ]]; then
        ok "    SANs    : ${csr_san_line}"
    else
        warn "    SANs    : run manually: openssl req -in ${local_csr} -noout -text"
    fi
}


#============================================================================
# PROCESS HOSTS FILE
# =============================================================================

process_hosts_file() {
    section "Processing hosts file: ${HOSTS_FILE}"

    local line_number=0
    local host_count=0
    local skip_count=0
    local error_count=0

    # AFTER — hosts file on fd3, SSH cannot touch it
    while IFS= read -r raw_line <&3; do
        line_number=$(( line_number + 1 ))

        if [[ -z "${raw_line//[[:space:]]/}" ]] || [[ "${raw_line}" =~ ^[[:space:]]*# ]]; then
            skip_count=$(( skip_count + 1 ))
            continue
        fi

        if parse_host_line "${raw_line}"; then
            host_count=$(( host_count + 1 ))
            generate_for_host "${PARSED_FQDN}" "${PARSED_IP}" "${PARSED_EXTRA}"
        else
            error "Skipping invalid line ${line_number}: ${raw_line}"
            error_count=$(( error_count + 1 ))
        fi

    done 3< "${HOSTS_FILE}"

    echo ""
    section "Run Summary"
    info "  Hosts attempted : ${host_count}"
    info "  Lines skipped   : ${skip_count} (blanks/comments)"

    if [[ ${error_count} -gt 0 ]]; then
        warn "  Parse errors    : ${error_count} — review lines above"
    else
        ok "  Parse errors    : 0"
    fi

    if [[ ${#FAILED_HOSTS[@]} -gt 0 ]]; then
        warn "  SSH/gen failures: ${#FAILED_HOSTS[@]}"
        for h in "${FAILED_HOSTS[@]}"; do
            warn "    - ${h}"
        done
        warn "  Fix SSH on failed hosts then re-run — completed hosts will be skipped."
    else
        ok "  SSH/gen failures: 0"
    fi
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================

print_final_summary() {
    section "Staged output under ${BASE_DIR}"
    find "${BASE_DIR}" \( -name "*.pem" -o -name "*.csr" -o -name "key.pwd" \) \
        | sort \
        | while read -r f; do
            printf "    %s\n" "${f}"
          done

    echo ""
    echo -e "${BOLD}Next Steps — Cloudera Auto-TLS (existing certificates flow):${RESET}"
    echo "  1. Submit each <fqdn>.csr to your CA for signing."
    echo "  2. Collect signed host certs + full CA chain."
    echo "  3. Invoke CM Auto-TLS API: generateCmca then importAdminCredentials."
    echo "  4. Restart CM and all managed services."
    echo ""
    echo -e "${YELLOW}  Shared passphrase : ${KEY_PWD_FILE}${RESET}"
    echo -e "${YELLOW}  Keep this safe — needed during CM API activation.${RESET}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  Cloudera Auto-TLS — Per-Node CSR & Key Generation        ${RESET}"
    echo -e "${BOLD}  Run from Cloudera Manager host with passwordless SSH        ${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    validate_args "$@"
    check_prerequisites
    setup_key_password
    process_hosts_file
    print_final_summary
}

main "$@"

