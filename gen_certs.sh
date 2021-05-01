#!/bin/sh
certdir="cert"
mkdir -p "${certdir}"
openssl genrsa -out "${certdir}/private.key" 2048
openssl req -new -x509 -days 3650 -key "${certdir}/private.key" -out "${certdir}/server.pem" -subj "/CN=*.acmecorp.com"
