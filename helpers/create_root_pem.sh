#!/bin/bash

openssl req -newkey rsa:8192 -sha1 -keyout rootkey.pem -out rootreq.pem
openssl x509 -req -in rootreq.pem -sha1 -extfile openssl.cnf -extensions v3_ca -signkey rootkey.pem -out rootcert.pem
cat rootcert.pem rootkey.pem > root.pem
openssl x509 -subject -issuer -noout -in root.pem