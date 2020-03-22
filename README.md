# keycloak-spi

Has recpatcha for login and does storage encryption/decryption of emails.

Generate your own local keys using the following: <br>

```openssl genrsa -out priv-key.pem 1024``` <br>

```openssl rsa -in priv-key.pem -outform PEM -pubout -out public.pem```

