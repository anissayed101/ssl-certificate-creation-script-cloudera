# SSL CSR Generation Scripts

This repository contains shell scripts to generate SSL private keys and Certificate Signing Requests (CSRs) for servers without requiring SSH access to the target machines.

The main use case is to generate CSRs centrally from one Linux machine when direct SSH access to the target servers is not available.

---

## Purpose

This script helps generate:

- Encrypted private key files
- Certificate Signing Request files
- Subject Alternative Names (SANs)
- Per-host output folders
- A shared private key passphrase file

It is useful when:

- SSH access to target servers is not available
- Target servers are Windows-based
- Target servers are restricted by firewall or network policy
- CSRs need to be generated centrally for multiple hosts
- SSL implementation is required for enterprise platforms such as Cloudera, Informatica, erwin, web applications, APIs, or internal services

---

## Repository Contents

```text
.
├── csr-generation.sh      # Generate key and CSR locally without SSH
├── csr-generation.sh            # Generate key and CSR using SSH mode
├── inventory.txt        # Example host inventory for SSH mode
└── inventory.txt               # Example host inventory for non-SSH/local CSR generation
```

---

## Recommended Script

For CSR generation without SSH, use:

```bash
./csr-generation.sh
```

This script runs fully on the local machine and generates the private key and CSR on behalf of the target server.

---

## Prerequisites

The script must be executed on a Linux machine.

Required tools:

- bash
- openssl
- coreutils
- grep
- cut
- tr

Validate whether the required tools are available:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

If any of the above commands are missing, install the required packages based on your operating system.

---

## Installing Required Tools

If the required tools are not already installed, use the relevant command based on your operating system.

### Red Hat / CentOS / Rocky Linux / AlmaLinux

For RHEL-based systems using `yum`:

```bash
sudo yum install -y openssl bash coreutils grep
```

For newer RHEL-based systems using `dnf`:

```bash
sudo dnf install -y openssl bash coreutils grep
```

Validate installation:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

### Ubuntu / Debian

For Ubuntu or Debian-based systems:

```bash
sudo apt update
sudo apt install -y openssl bash coreutils grep
```

Validate installation:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

### SUSE Linux / SLES / openSUSE

For SUSE-based systems:

```bash
sudo zypper refresh
sudo zypper install -y openssl bash coreutils grep
```

Validate installation:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

### Amazon Linux

For Amazon Linux 2:

```bash
sudo yum install -y openssl bash coreutils grep
```

For Amazon Linux 2023:

```bash
sudo dnf install -y openssl bash coreutils grep
```

Validate installation:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

### Oracle Linux

For Oracle Linux using `yum`:

```bash
sudo yum install -y openssl bash coreutils grep
```

For Oracle Linux using `dnf`:

```bash
sudo dnf install -y openssl bash coreutils grep
```

Validate installation:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

### Minimal Linux Servers

On minimal Linux installations, some commands may be missing.

Install the required packages using the package manager available on the server.

After installation, validate again:

```bash
openssl version
bash --version
which grep
which cut
which tr
```

---

## Make the Script Executable

Before running the script, provide execute permission:

```bash
chmod +x csr-generation.sh
```

---

## Host File Format

Create or update a inventory file using the following format:

```text
fqdn|ip|extra_sans
```

Example:

```text
server1.test.local|10.10.10.11|
server2.test.local|10.10.10.12|
server3.test.local|10.10.10.13|
```

The third field, `extra_sans`, is optional.

Example with additional SANs:

```text
server1.test.local|10.10.10.11|DNS:server1,DNS:server1-alias.test.local,IP:10.10.10.21
```

---

## How to Run

Run the script with the inventory file as input:

```bash
./csr-generation.sh inventory.txt
```

Example:

```bash
./csr-generation.sh inventory.txt
```

---

## Output Location

By default, the script writes output to:

```text
/tmp/auto-tls/
```

Example output structure:

```text
/tmp/auto-tls/
├── keys/
│   └── key.pwd
├── server1.test.local/
│   ├── server1.test.local-key.pem
│   └── server1.test.local.csr
├── server2.test.local/
│   ├── server2.test.local-key.pem
│   └── server2.test.local.csr
└── server3.test.local/
    ├── server3.test.local-key.pem
    └── server3.test.local.csr
```

---

## Files Generated Per Host

For every host, the script generates:

| File | Description |
|---|---|
| `<fqdn>-key.pem` | Encrypted private key |
| `<fqdn>.csr` | Certificate Signing Request to be submitted to the Certificate Authority |

Example:

```text
server1.test.local-key.pem
server1.test.local.csr
```

---

## Key Password

The script creates a shared key password file:

```text
/tmp/auto-tls/keys/key.pwd
```

This password is used to encrypt the generated private keys.

If the file already exists, the script reuses it.

To generate a new password, remove the existing file before running the script again:

```bash
rm -f /tmp/auto-tls/keys/key.pwd
```

Then rerun the script:

```bash
./csr-generation.sh inventory.txt
```

---

## Certificate Subject Details

The script can be configured with certificate subject values.

Example:

```bash
CERT_C="AE"
CERT_ST="State"
CERT_L="City"
CERT_O="Example Organization"
CERT_OU="Information Technology"
```

The Common Name is automatically set to the FQDN of each host.

Example subject:

```text
/C=AE/ST=State/L=City/O=Example Organization/OU=Information Technology/CN=server1.test.local
```

You can update these values inside the script based on the target environment, project, or internal certificate policy.

---

## SAN Values

For each host, the script automatically includes:

```text
DNS:<fqdn>
DNS:<short-hostname>
IP:<ip-address>
```

Example:

```text
DNS:server1.test.local,DNS:server1,IP:10.10.10.11
```

Additional SANs can be added in the third column of the inventory file.

Example:

```text
server1.test.local|10.10.10.11|DNS:server1-alias.test.local,IP:10.10.10.21
```

---

## Validate Generated CSR

To check the CSR content:

```bash
openssl req -in /tmp/auto-tls/<fqdn>/<fqdn>.csr -noout -text
```

Example:

```bash
openssl req -in /tmp/auto-tls/server1.test.local/server1.test.local.csr -noout -text
```

To check the CSR subject:

```bash
openssl req -in /tmp/auto-tls/<fqdn>/<fqdn>.csr -noout -subject
```

Example:

```bash
openssl req -in /tmp/auto-tls/server1.test.local/server1.test.local.csr -noout -subject
```

To verify the CSR signature:

```bash
openssl req -in /tmp/auto-tls/<fqdn>/<fqdn>.csr -noout -verify
```

Example:

```bash
openssl req -in /tmp/auto-tls/server1.test.local/server1.test.local.csr -noout -verify
```

---

## Submit CSR to Certificate Authority

Submit only the `.csr` file to the Certificate Authority.

Submit:

```text
<fqdn>.csr
```

Do not submit or share:

```text
<fqdn>-key.pem
key.pwd
```

The private key and password file must remain secure on the machine where they were generated.

---

## Regenerating CSR for a Host

If a CSR already exists, the script may skip that host.

To regenerate the CSR for a specific host, remove that host's output folder:

```bash
rm -rf /tmp/auto-tls/<fqdn>
```

Example:

```bash
rm -rf /tmp/auto-tls/server1.test.local
```

Then run the script again:

```bash
./csr-generation.sh inventory.txt
```

---

## Example End-to-End Usage

Create a inventory file:

```bash
vi inventory.txt
```

Add sample hosts:

```text
server1.test.local|10.10.10.11|
server2.test.local|10.10.10.12|
server3.test.local|10.10.10.13|
```

Make the script executable:

```bash
chmod +x csr-generation.sh
```

Run the script:

```bash
./csr-generation.sh inventory.txt
```

Validate one CSR:

```bash
openssl req -in /tmp/auto-tls/server1.test.local/server1.test.local.csr -noout -text
```

Submit only the CSR file to the Certificate Authority:

```text
/tmp/auto-tls/server1.test.local/server1.test.local.csr
```

Keep the private key and password file secure:

```text
/tmp/auto-tls/server1.test.local/server1.test.local-key.pem
/tmp/auto-tls/keys/key.pwd
```

---

## Important Security Notes

Do not commit generated keys, CSRs, passwords, or certificate files to GitHub.

The following files and folders should not be pushed:

```text
/tmp/auto-tls/
*.key
*-key.pem
*.csr
*.crt
*.cer
*.p7b
*.jks
*.p12
*.pfx
key.pwd
```

Recommended `.gitignore`:

```gitignore
# Generated certificate material
auto-tls/
tmp/
*.key
*-key.pem
*.csr
*.crt
*.cer
*.pem
*.p7b
*.p12
*.pfx
*.jks
*.keystore
*.truststore
key.pwd

# OS/editor files
.DS_Store
.vscode/
.idea/
```

Only commit the scripts and sanitized sample inventory files.

Avoid committing real client hostnames, IP addresses, keys, CSRs, or certificates to GitHub.

---

## Client Data Sanitization

Before pushing this repository to GitHub, ensure that all files are sanitized.

Remove or replace:

- Real client names
- Real client domains
- Real hostnames
- Real IP addresses
- Generated private keys
- Generated CSRs
- Generated certificates
- Password files
- Environment-specific paths

Use safe sample values such as:

```text
server1.test.local|10.10.10.11|
server2.test.local|10.10.10.12|
server3.test.local|10.10.10.13|
```

Also update sample files such as:

```text
inventory.txt
inventory.txt
```

Replace any real values with generic examples:

```text
server1.test.local|10.10.10.11|
server2.test.local|10.10.10.12|
server3.test.local|10.10.10.13|
```

---

## FIPS Note

The script may use:

```bash
KEY_BITS=4096
```

For FIPS-enabled environments, RSA 4096 may not be accepted depending on the system policy.

For FIPS-enabled servers, update the script to use:

```bash
KEY_BITS=2048
```

or:

```bash
KEY_BITS=3072
```

Confirm the allowed key size with the organization’s security or certificate policy.

---

## Notes

- The script does not require SSH to the target hosts.
- The private key is generated locally.
- The CSR is generated using the target server FQDN and IP address.
- The certificate returned by the Certificate Authority must be installed together with the matching private key.
- The private key must remain protected and should not be shared publicly.
- The inventory file should contain only approved internal hostnames and IP addresses.
- Avoid committing real client hostnames, IP addresses, keys, CSRs, or certificates to GitHub.

---

## Disclaimer

This script is intended for internal SSL and CSR automation activities.

Review and adjust the certificate subject, SAN values, key size, output path, password handling, and security controls according to your organization’s certificate policy before using it in production.
