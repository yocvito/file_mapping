# file_mapping
basic SSL server to map a specific directory and allow downloading files from it 

generate certificate and key with
```
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout key.pem -out mycert.pem
```
