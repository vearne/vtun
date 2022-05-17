#!bin/bash

domain="vtun.org"
email="admin@vtun.org"

echo "make cert"
openssl req -new -nodes -x509 -out ./certs/client.pem -keyout ./certs/client.key -days 3650 -subj "/C=DE/ST=NRW/L=Earth/O=Random Company/OU=IT/CN=$domain/emailAddress=$email"

