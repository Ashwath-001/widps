#!/bin/bash
# Creates a private CA and a server certificate for the sensor under /etc/widps/tls.
# Usage: sudo bash deploy/make-local-ca.sh <hostname> [ip]
# Then import /etc/widps/tls/ca.crt into the browsers that use the console.
set -euo pipefail

HOST="${1:?usage: make-local-ca.sh <hostname> [ip]}"
IP="${2:-}"
DIR=/etc/widps/tls
DAYS_CA=1825
DAYS_SERVER=397

if [ "$EUID" -ne 0 ]; then
    echo "run as root: sudo bash deploy/make-local-ca.sh $HOST $IP"
    exit 1
fi

install -d -m 700 "$DIR"
cd "$DIR"
umask 077

if [ ! -f ca.key ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -key ca.key -sha256 -days "$DAYS_CA" -subj "/CN=WIDPS Local CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
    echo "created CA: $DIR/ca.crt"
fi

SAN="DNS:$HOST"
[ -n "$IP" ] && SAN="$SAN,IP:$IP"

openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=$HOST" -out server.csr
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS_SERVER" -sha256 \
    -extfile server.ext -out server.crt
rm -f server.csr server.ext

chmod 600 ca.key server.key
chmod 644 ca.crt server.crt
chown root:root ./*
echo "server certificate for $SAN: $DIR/server.crt (valid $DAYS_SERVER days)"
echo "import $DIR/ca.crt into each browser/OS trust store, then: sudo nginx -t && sudo systemctl reload nginx"
