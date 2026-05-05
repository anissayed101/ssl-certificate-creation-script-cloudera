#!/usr/bin/env bash
# =============================================================================
# generate_csr_local.sh
# Generate private key + CSR locally on THIS host on behalf of any server
#
# PURPOSE:
#   Runs entirely on the CM host (utility2). No SSH, no remote access needed.
#   Use this for servers you cannot SSH into:
#     - Informatica Staging (Linux, no SSH)
#     - ERwin Production (Windows)
#     - Any other server
#
# USAGE:
#   ./generate_csr_local.sh <hosts_file>
#
# HOSTS FILE FORMAT (pipe-delimited):
#   fqdn|ip|extra_sans
#
#   Examples:
#     cdp-master1.cloudera.bbi|192.168.113.131|
#     server2.example.local|10.10.10.12|
#
# OUTPUT:
#   /tmp/auto-tls/<fqdn>/
#     <fqdn>-key.pem   <- private key (encrypted)
#     <fqdn>.csr       <- CSR to submit to CA
#   /tmp/auto-tls/keys/key.pwd
#
# FIPS NOTE:
#   FIPS clusters must use rsa:2048 or rsa:3072. Change KEY_BITS below.
# =============================================================================
set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

CERT_C="AE"
CERT_ST="Dubai"
CERT_L="Dubai"
CERT_O="BBI"
CERT_OU=""

# 4096 for non-FIPS. FIPS clusters: use 2048 or 3072.
KEY_BITS=4096
DIGEST="sha256"
CERT_DAYS=365

BASE_DIR="/tmp/auto-tls"
KEY_PWD_DIR="${BASE_DIR}/keys"
KEY_PWD_FILE="${KEY_PWD_DIR}/key.pwd"
PWD_LENGTH=32

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
    section "Checking prerequisites"
    local missing=0
    for cmd in openssl cut tr grep sed find sort head; do
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
        echo "  Examples:"
        echo "    cdp-master1.cloudera.bbi|192.168.113.131|"
        echo "    server2.example.local|10.10.10.12|"
        exit 1
    fi
    HOSTS_FILE="$1"
    if [[ ! -f "${HOSTS_FILE}" ]]; then
        error "Hosts file not found: ${HOSTS_FILE}"
        exit 1
    fi
}

# =============================================================================
# KEY PASSWORD — reuse existing key.pwd if present so all certs share one
# =============================================================================

setup_key_password() {
    section "Setting up shared key password"
    mkdir -p "${KEY_PWD_DIR}"
    chmod 700 "${KEY_PWD_DIR}"

    if [[ -f "${KEY_PWD_FILE}" ]]; then
        warn "key.pwd already exists — reusing existing passphrase."
        warn "  All keys will use: ${KEY_PWD_FILE}"
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
# =============================================================================

parse_host_line() {
    local raw_line="$1"
    PARSED_FQDN=$(echo "${raw_line}" | cut -d'|' -f1 | tr -d '[:space:]')
    PARSED_IP=$(  echo "${raw_line}" | cut -d'|' -f2 | tr -d '[:space:]')
    PARSED_EXTRA=$(echo "${raw_line}" | cut -d'|' -f3 | tr -d '[:space:]')

    if [[ -z "${PARSED_FQDN}" ]]; then
        error "Empty FQDN in line: ${raw_line}"; return 1
    fi
    if [[ -z "${PARSED_IP}" ]]; then
        error "Empty IP for host '${PARSED_FQDN}'"; return 1
    fi
    if ! echo "${PARSED_FQDN}" | \
         grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        error "Invalid FQDN: ${PARSED_FQDN}"; return 1
    fi
    if ! echo "${PARSED_IP}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        error "Invalid IP: ${PARSED_IP}"; return 1
    fi
    return 0
}



# =============================================================================
# GENERATE KEY + CSR LOCALLY ON BEHALF OF THE TARGET HOST
# =============================================================================

generate_for_host() {
    local fqdn="$1"
    local ip="$2"
    local extra_sans="$3"

    local host_dir="${BASE_DIR}/${fqdn}"
    local key_file="${host_dir}/${fqdn}-key.pem"
    local csr_file="${host_dir}/${fqdn}.csr"

    local short_name
    short_name=$(echo "${fqdn}" | cut -d'.' -f1)

    section "Processing: ${fqdn}"
    info "  IP          : ${ip}"
    info "  Short name  : ${short_name}"
    info "  Extra SANs  : ${extra_sans:-<none>}"

    # Skip if already done
    if [[ -f "${key_file}" ]] && [[ -f "${csr_file}" ]]; then
        warn "Already exists — skipping. Remove ${host_dir}/ to regenerate."
        return 0
    fi

    mkdir -p "${host_dir}"
    chmod 700 "${host_dir}"

    # Build SAN string
    local san_string="DNS:${fqdn},DNS:${short_name},IP:${ip}"
    if [[ -n "${extra_sans}" ]]; then
        san_string="${san_string},${extra_sans}"
    fi

    local subject="/C=${CERT_C}/ST=${CERT_ST}/L=${CERT_L}/O=${CERT_O}"

    if [[ -n "${CERT_OU}" ]]; then
        subject="${subject}/OU=${CERT_OU}"
    fi

    subject="${subject}/CN=${fqdn}"

    info "  SANs        : ${san_string}"
    info "  Subject     : ${subject}"
    info "  Generating ${KEY_BITS}-bit RSA key + CSR locally..."

    openssl req \
        -newkey    "rsa:${KEY_BITS}" \
        -"${DIGEST}" \
        -days      "${CERT_DAYS}" \
        -keyout    "${key_file}" \
        -out       "${csr_file}" \
        -passout   "file:${KEY_PWD_FILE}" \
        -subj      "${subject}" \
        -reqexts   san \
        -config <(
            printf '[req]\ndistinguished_name=req\nreq_extensions=san\n[san]\nsubjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' \
                   "${san_string}"
        ) \
        2>/dev/null

    chmod 600 "${key_file}"
    chmod 644 "${csr_file}"

    ok "  Key : ${key_file}"
    ok "  CSR : ${csr_file}"

    # Verify
    info "  Verifying CSR..."
    local csr_subject
    csr_subject=$(openssl req -in "${csr_file}" -noout -subject 2>/dev/null)
    info "    Subject : ${csr_subject}"

    local san_line
    san_line=$(openssl req -in "${csr_file}" -noout -text 2>/dev/null \
               | grep -A1 'Subject Alternative Name' | tail -1 \
               | sed 's/^[[:space:]]*//' || true)
    if [[ -n "${san_line}" ]]; then
        ok "    SANs    : ${san_line}"
    else
        warn "    SANs not visible — verify: openssl req -in ${csr_file} -noout -text"
    fi

    local eku_line
    eku_line=$(openssl req -in "${csr_file}" -noout -text 2>/dev/null \
               | grep -A1 'Extended Key Usage' | tail -1 \
               | sed 's/^[[:space:]]*//' || true)
    if [[ -n "${eku_line}" ]]; then
        ok "    EKU     : ${eku_line}"
    fi
}



# =============================================================================
# PROCESS HOSTS FILE
# =============================================================================

process_hosts_file() {
    section "Processing hosts file: ${HOSTS_FILE}"

    local line_number=0
    local host_count=0
    local skip_count=0
    local error_count=0

    # fd3 prevents any subshell from consuming the hosts file via stdin
    while IFS= read -r raw_line <&3 || [[ -n "${raw_line}" ]]; do
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
    info "  Hosts processed : ${host_count}"
    info "  Lines skipped   : ${skip_count} (blanks/comments)"
    if [[ ${error_count} -gt 0 ]]; then
        warn "  Parse errors    : ${error_count} — review lines above"
    else
        ok "  Parse errors    : 0"
    fi
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================

print_final_summary() {
    section "Output under ${BASE_DIR}"
    find "${BASE_DIR}" \( -name "*.pem" -o -name "*.csr" -o -name "key.pwd" \) \
        | sort \
        | while read -r f; do
            printf "    %s\n" "${f}"
          done

    echo ""
    echo -e "${BOLD}Next Steps:${RESET}"
    echo "  1. Submit each <fqdn>.csr to your CA for signing."
    echo "  2. For Linux servers  : copy signed cert + key back to that server."
    echo "  3. For Windows servers: import signed cert + key via Windows cert store."
    echo "  4. For Cloudera nodes : proceed with Auto-TLS API activation."
    echo ""
    echo -e "${YELLOW}  Shared passphrase : ${KEY_PWD_FILE}${RESET}"
    echo -e "${YELLOW}  Keep this safe — needed for all key operations.${RESET}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  CSR & Key Generation — Local / On-Behalf-Of Mode        ${RESET}"
    echo -e "${BOLD}  Run locally from any Linux host — no SSH required            ${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    validate_args "$@"
    check_prerequisites
    setup_key_password
    process_hosts_file
    print_final_summary
}

main "$@"



