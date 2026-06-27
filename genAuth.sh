python3 -c "import secrets, string; \
  chars = string.ascii_letters + string.digits; \
  print('PROXY_USER=' + secrets.token_hex(8)); \
  print('PROXY_PASS=' + secrets.token_hex(12))" > .env

echo Auth creds was generated into .env file