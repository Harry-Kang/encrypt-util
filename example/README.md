# EXAMPLE
## 生成私钥
`$ openssl genrsa -out rsa_private_key.pem 2048`
## 将私钥转换成PKCS8格式
`$ openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem`
## 生成公钥
`$ openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem`

## tips
上述三条命令执行完成后会生成开发者可以在当前文件夹中，看到rsa_private_key.pem（开发者RSA私钥）、rsa_private_key_pkcs8.pem（pkcs8格式开发者RSA私钥）和rsa_public_key.pem（开发者RSA公钥）3个文件。
