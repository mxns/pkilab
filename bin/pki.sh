#!/bin/sh

ROOT_SUBJECT="/C=SE/ST=Stockholm/O=Codeus/OU=Test/CN=Codeus Test Root CA"
ROOT_CONFIG_FILE="/opt/ca/openssl.cnf"
ROOT_PRIVATE_KEY_FILE="/opt/ca/private/ca.key.pem"
ROOT_CERT_FILE="/opt/ca/certs/ca.cert.pem"
ROOT_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"
ROOT_KEY_STRENGTH=4096
ROOT_VALID_DAYS=12

INTERMEDIATE_SUBJECT="/C=SE/ST=Stockholm/O=Codeus/OU=Test/CN=Codeus Test Root CA"
INTERMEDIATE_CONFIG_FILE="/opt/ca/intermediate/openssl.cnf"
INTERMEDIATE_PRIVATE_KEY_FILE="/opt/ca/intermediate/private/intermediate.key.pem"
INTERMEDIATE_CERT_FILE="/opt/ca/intermediate/certs/intermediate.cert.pem"
INTERMEDIATE_KEY_STRENGTH=2048
INTERMEDIATE_VALID_DAYS=3

HOST_SUBJECT="/C=SE/ST=Nacka/L=Nacka Strand/O=Example/OU=Testers/CN=127.0.0.1"
HOST_KEY_STRENGTH=2048
HOST_VALID_DAYS=2

CLIENT_SUBJECT="/CN=cborgstrom"
CLIENT_KEY_STRENGTH=1024
CLIENT_VALID_DAYS=1

create_cert_and_key_pair() {
  while getopts "K:P:S:D:c:E:p:" arg; do
    case ${arg} in
    K)
      key_strength=${OPTARG}
      ;;
    S)
      subject=${OPTARG}
      ;;
    D)
      valid_days=${OPTARG}
      ;;
    c)
      ca_config=${OPTARG}
      ;;
    E)
      extensions=${OPTARG}
      ;;
    p)
      ca_pass=${OPTARG}
      ;;
    *)
      ;;
    esac
  done

  csr_file="$(pwd)/tmp.csr"
  key_file="$(pwd)/tmp.key"
  CURRENT_PRIVATE_KEY_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"

  # Key and CSR
  openssl req -new -sha256 -batch -out "${csr_file}" -keyout "${key_file}" -newkey "rsa:${key_strength}" -passout "pass:${CURRENT_PRIVATE_KEY_PASS}" -subj "${subject}"

  # Certificate from CSR
  CURRENT_CERT=$(openssl ca -notext -md sha256 -batch -in "${csr_file}" -config "${ca_config}" -extensions "${extensions}" -days "${valid_days}" -passin "pass:${ca_pass}")

  # Extract public key
  CURRENT_PUBLIC_KEY=$(< "${key_file}" openssl rsa -pubout -outform pem -passin "pass:${CURRENT_PRIVATE_KEY_PASS}")

  # Extract private key
  CURRENT_PRIVATE_KEY=$(< "${key_file}" openssl rsa -outform pem -passin "pass:${CURRENT_PRIVATE_KEY_PASS}")
}

# Root key and certificate
openssl genrsa -aes256 -passout "pass:${ROOT_PASS}" -out ${ROOT_PRIVATE_KEY_FILE} ${ROOT_KEY_STRENGTH}
openssl req -new -x509 -sha256 -batch -extensions "v3_ca" -config ${ROOT_CONFIG_FILE} -key ${ROOT_PRIVATE_KEY_FILE} -passin "pass:${ROOT_PASS}" -days ${ROOT_VALID_DAYS} -subj "${ROOT_SUBJECT}" -out ${ROOT_CERT_FILE}
ROOT_PUBLIC_KEY=$(< "${ROOT_PRIVATE_KEY_FILE}" openssl rsa -pubout -outform pem -passin "pass:${ROOT_PASS}")
ROOT_PRIVATE_KEY=$(< "${ROOT_PRIVATE_KEY_FILE}" openssl rsa -outform pem -passin "pass:${ROOT_PASS}")
ROOT_CERT=$(cat "$ROOT_CERT_FILE")
CERT_CHAIN=$ROOT_CERT
printf 'R|%s|%s|%s|%s\n' "$(echo "$ROOT_PUBLIC_KEY" | base64 -w 0)" "$(echo "$ROOT_PRIVATE_KEY" | base64 -w 0)" "$(echo "$ROOT_CERT" | base64 -w 0)" "$(echo "$CERT_CHAIN" | base64 -w 0)"

# Intermediate key and certificate
create_cert_and_key_pair -K ${INTERMEDIATE_KEY_STRENGTH} -S "${INTERMEDIATE_SUBJECT}" -D ${INTERMEDIATE_VALID_DAYS} -E "v3_intermediate_ca" -c ${ROOT_CONFIG_FILE} -p "${ROOT_PASS}"
printf '%s' "${CURRENT_CERT}"        > ${INTERMEDIATE_CERT_FILE}
printf '%s' "${CURRENT_PRIVATE_KEY}" > ${INTERMEDIATE_PRIVATE_KEY_FILE}
INTERMEDIATE_PASS="$CURRENT_PRIVATE_KEY_PASS"
CERT_CHAIN="${CURRENT_CERT}"'
'"${CERT_CHAIN}"
printf 'I|%s|%s|%s|%s\n' "$(echo "$CURRENT_PUBLIC_KEY" | base64 -w 0)" "$(echo "$CURRENT_PRIVATE_KEY" | base64 -w 0)" "$(echo "$CURRENT_CERT" | base64 -w 0)" "$(printf '%s' "$CERT_CHAIN" | base64 -w 0)"

# Host key and certificate
create_cert_and_key_pair -K ${HOST_KEY_STRENGTH} -S "${HOST_SUBJECT}" -D ${HOST_VALID_DAYS} -E "server_cert" -c ${INTERMEDIATE_CONFIG_FILE} -p "${INTERMEDIATE_PASS}"
printf 'H|%s|%s|%s|%s\n' "$(echo "$CURRENT_PUBLIC_KEY" | base64 -w 0)" "$(echo "$CURRENT_PRIVATE_KEY" | base64 -w 0)" "$(echo "$CURRENT_CERT" | base64 -w 0)" "$(printf '%s' "$CERT_CHAIN" | base64 -w 0)"

# Client key and certificate
create_cert_and_key_pair -K ${CLIENT_KEY_STRENGTH} -S "${CLIENT_SUBJECT}" -D ${CLIENT_VALID_DAYS} -E "usr_cert" -c ${INTERMEDIATE_CONFIG_FILE} -p "${INTERMEDIATE_PASS}"
printf 'C|%s|%s|%s|%s\n' "$(echo "$CURRENT_PUBLIC_KEY" | base64 -w 0)" "$(echo "$CURRENT_PRIVATE_KEY" | base64 -w 0)" "$(echo "$CURRENT_CERT" | base64 -w 0)" "$(printf '%s' "$CERT_CHAIN" | base64 -w 0)"
