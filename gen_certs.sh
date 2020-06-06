#!/bin/bash
openssl genrsa -out cert/private.key 2048
openssl req -new -x509 -days 3650 -key cert/private.key -out cert/server.pem -subj "/CN=*.acmecorp.com"
