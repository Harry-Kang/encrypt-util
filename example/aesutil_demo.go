package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/Harry-Kang/encrypt-util/aesutil"
)

var (
	origin = "hello, 康熙大哥哥。"
	key    = "ZZ9fu/S077QFEINDWGNMdw=="
)

func init() {
	h := md5.New()
	h.Write([]byte(origin))
	v := h.Sum(nil)
	key = base64.StdEncoding.EncodeToString(v)
}

func aesCFBDemo() {
	fmt.Printf("\n\n================ AES CFB DEMO ========================\n")

	cipherText, err := aesutil.Encrypt([]byte(origin), []byte(key), aesutil.IV)
	if err != nil {
		panic("aesutil encrypt err:" + err.Error())
	}
	fmt.Println("base64 cipherText:", base64.StdEncoding.EncodeToString(cipherText))

	plainText, err := aesutil.Decrypt(cipherText, []byte(key), aesutil.IV)
	if err != nil {
		panic("aesutil decrypt err:" + err.Error())
	}
	fmt.Println("plainText:", string(plainText))
}

func aesCBCDemo() {
	fmt.Printf("\n\n================ AES CBC DEMO ========================\n")

	cipherText, err := aesutil.CBCEncrypt([]byte(origin), []byte(key), aesutil.IV, aesutil.PKCS5Padding)
	if err != nil {
		panic("aesutil encrypt err:" + err.Error())
	}
	fmt.Println("base64 cipherText:", base64.StdEncoding.EncodeToString(cipherText))

	plainText, err := aesutil.CBCDecrypt(cipherText, []byte(key), aesutil.IV, aesutil.PKCS5Padding)
	if err != nil {
		panic("aesutil decrypt err:" + err.Error())
	}
	fmt.Println("plainText:", string(plainText))
}

func main() {
	aesCFBDemo()
	aesCBCDemo()
}
