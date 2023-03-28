#!/bin/sh

ROOT_SUBJECT="/C=SE/ST=Stockholm/O=Codeus/OU=Test/CN=Codeus Test Root CA"
CA_CONFIG_FILE="/opt/ca/openssl.cnf"
ROOT_PRIVATE_KEY_FILE="/opt/ca/private/ca.key.pem"
ROOT_CERT_FILE="/opt/ca/certs/ca.cert.pem"
CA_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"
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
  _KEY_FILE="$(pwd)/tmp.key"
  CURRENT_PRIVATE_KEY_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"

  # Key and CSR
  openssl req -new -sha256 -batch -out "${csr_file}" -keyout "${_KEY_FILE}" -newkey "rsa:${key_strength}" -passout "pass:${CURRENT_PRIVATE_KEY_PASS}" -subj "${subject}"

  # Certificate from CSR
  _CERT=$(openssl ca -notext -md sha256 -batch -in "${csr_file}" -config "${ca_config}" -extensions "${extensions}" -days "${valid_days}" -passin "pass:${ca_pass}")

  # Extract public key
  _PUBLIC_KEY=$(< "${_KEY_FILE}" openssl rsa -pubout -outform pem -passin "pass:${CURRENT_PRIVATE_KEY_PASS}")

  # Extract private key
  _PRIVATE_KEY=$(< "${_KEY_FILE}" openssl rsa -outform pem -passin "pass:${CURRENT_PRIVATE_KEY_PASS}" -passout "pass:${CURRENT_PRIVATE_KEY_PASS}")
}

# Root key and certificate
openssl genrsa -aes256 -passout "pass:${CA_PASS}" -out ${ROOT_PRIVATE_KEY_FILE} ${ROOT_KEY_STRENGTH}
openssl req -new -x509 -sha256 -batch -extensions "v3_ca" -config ${CA_CONFIG_FILE} -key ${ROOT_PRIVATE_KEY_FILE} -passin "pass:${CA_PASS}" -days ${ROOT_VALID_DAYS} -subj "${ROOT_SUBJECT}" -out ${ROOT_CERT_FILE}
CERT_CHAIN=$(cat $ROOT_CERT_FILE)
PUBLIC_KEY=$(openssl x509 -pubkey -noout -in $ROOT_CERT_FILE | base64 -w 0)
PRIVATE_KEY=$(< $ROOT_PRIVATE_KEY_FILE base64 -w 0)
CERT=$(< "$ROOT_CERT_FILE" base64 -w 0)
printf 'R|%s|%s|%s|%s\n' "$PUBLIC_KEY" "$PRIVATE_KEY" "$CERT" "$(echo "$CERT_CHAIN" | base64 -w 0)"

csr_file="$(pwd)/tmp.csr"
key_file="$(pwd)/tmp.key"
cert_file="$(pwd)/tmp.crt"
p12_file="$(pwd)/tmp.p12"
INTERMEDIATE_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"

# Intermediate key and certificate
openssl req -new -sha256 -batch -out "${csr_file}" -newkey "rsa:${INTERMEDIATE_KEY_STRENGTH}" -keyout "${INTERMEDIATE_PRIVATE_KEY_FILE}" -passout "pass:${INTERMEDIATE_PASS}" -subj "${INTERMEDIATE_SUBJECT}"
openssl ca -notext -md sha256 -batch -in "${csr_file}" -config "${CA_CONFIG_FILE}" -passin "pass:${CA_PASS}" -extensions "v3_intermediate_ca" -days "${INTERMEDIATE_VALID_DAYS}" -out ${INTERMEDIATE_CERT_FILE}
CERT_CHAIN="$(cat $INTERMEDIATE_CERT_FILE $ROOT_CERT_FILE)"
CERT_CHAIN="$(cat $INTERMEDIATE_CERT_FILE $ROOT_CERT_FILE)"
PUBLIC_KEY=$(openssl x509 -pubkey -noout -in $INTERMEDIATE_CERT_FILE | base64 -w 0)
PRIVATE_KEY=$(< $INTERMEDIATE_PRIVATE_KEY_FILE base64 -w 0)
CERT=$(< "$INTERMEDIATE_CERT_FILE" base64 -w 0)
printf 'I|%s|%s|%s|%s\n' "$PUBLIC_KEY" "$PRIVATE_KEY" "$CERT" "$(echo "$CERT_CHAIN" | base64 -w 0)"

PASSWORD="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo)"

# Host key and certificate
openssl req -new -sha256 -batch -out "${csr_file}" -newkey "rsa:${HOST_KEY_STRENGTH}" -keyout "${key_file}" -passout "pass:${PASSWORD}" -subj "${HOST_SUBJECT}"
openssl ca -notext -md sha256 -batch -in "${csr_file}" -config "${INTERMEDIATE_CONFIG_FILE}" -passin "pass:${INTERMEDIATE_PASS}" -extensions "server_cert" -days "${HOST_VALID_DAYS}" -out "${cert_file}"
openssl pkcs12 -passin "pass:${PASSWORD}" -passout pass:serverpass -export -in "${cert_file}" -inkey "${key_file}" -name "Server" -out "${p12_file}.server"
PUBLIC_KEY=$(openssl x509 -pubkey -noout -in "${cert_file}" | base64 -w 0)
PRIVATE_KEY=$(< "$key_file" base64 -w 0)
CERT=$(< "${cert_file}" base64 -w 0)
P12=$(< "${p12_file}.server" base64 -w 0)
printf 'H|%s|%s|%s|%s|%s\n' "$PUBLIC_KEY" "$PRIVATE_KEY" "$CERT" "$(echo "$CERT_CHAIN" | base64 -w 0)" "$P12"

# Host key and certificate
openssl req -new -sha256 -batch -out "${csr_file}" -newkey "rsa:${CLIENT_KEY_STRENGTH}" -keyout "${key_file}" -passout "pass:${PASSWORD}" -subj "${CLIENT_SUBJECT}"
openssl ca -notext -md sha256 -batch -in "${csr_file}" -config "${INTERMEDIATE_CONFIG_FILE}" -passin "pass:${INTERMEDIATE_PASS}" -extensions "usr_cert" -days "${CLIENT_VALID_DAYS}" -out "${cert_file}"
openssl pkcs12 -passin "pass:${PASSWORD}" -passout pass:serverpass -export -in "${cert_file}" -inkey "${key_file}" -name "Client" -out "${p12_file}.client"
PUBLIC_KEY=$(openssl x509 -pubkey -noout -in "${cert_file}" | base64 -w 0)
PRIVATE_KEY=$(< "$key_file" base64 -w 0)
CERT=$(< "${cert_file}" base64 -w 0)
P12=$(< "${p12_file}.client" base64 -w 0)
printf 'H|%s|%s|%s|%s|%s\n' "$PUBLIC_KEY" "$PRIVATE_KEY" "$CERT" "$(echo "$CERT_CHAIN" | base64 -w 0)" "$P12"
