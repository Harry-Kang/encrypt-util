package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/intrsokx/encrypt-util/aesutil/ecb"
)

//default iv
var IV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

//default encrypt is cfb encrypted
func Encrypt(origData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = IV
	}

	if aes.BlockSize != len(iv) {
		return nil, errors.New("IV length must equal block size")
	}

	cfbEncrypter := cipher.NewCFBEncrypter(block, iv)

	cipherText := make([]byte, len(origData))
	cfbEncrypter.XORKeyStream(cipherText, origData)

	return cipherText, nil
}

func Decrypt(cipheredData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if aes.BlockSize != len(iv) {
		return nil, errors.New("IV length must equal block size")
	}

	cfbDecrypter := cipher.NewCFBDecrypter(block, iv)

	plainText := make([]byte, len(cipheredData))
	cfbDecrypter.XORKeyStream(plainText, cipheredData)

	return plainText, nil
}

type PadingFunc func([]byte) []byte

func CBCEncrypt(origData, key, iv []byte, padingFun PadingFunc) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = IV
	}

	if aes.BlockSize != len(iv) {
		return nil, errors.New("IV length must equal block size")
	}

	//加密（1、先填充数据。 2、再加密）
	origData = padingFun(origData)
	dst := make([]byte, len(origData))

	cbcEncrypter := cipher.NewCBCEncrypter(block, iv)
	cbcEncrypter.CryptBlocks(dst, origData)

	return dst, nil
}

func CBCDecrypt(cipherData, key, iv []byte, unPadingFun PadingFunc) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = IV
	}

	if aes.BlockSize != len(iv) {
		return nil, errors.New("IV length must equal block size")
	}

	//解密（1、先解密。 2、再去除填充数据）
	dst := make([]byte, len(cipherData))
	cbcDecrypter := cipher.NewCBCDecrypter(block, iv)
	cbcDecrypter.CryptBlocks(dst, cipherData)

	return unPadingFun(dst), nil
}

//一些跟aes加密相关的数据填充方法
func PKCS5Padding(origData []byte) []byte {
	padLength := aes.BlockSize - len(origData)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padLength)}, padLength)

	return append(origData, padText...)
}

func PKCS5UnPadding(cipherData []byte) []byte {
	length := len(cipherData)
	padLength := int(cipherData[length-1])

	return cipherData[:(length - padLength)]
}

/**
zeroPadding的话，有个特殊情况的bug，不推荐使用。

假设 originData = []byte{byte(0), byte(0), byte(0)}
padding后 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
在zeroUnPadding后就会变成一个空的字节数组。而不是originData
*/
func ZeroPadding(origData []byte) []byte {
	padLength := aes.BlockSize - len(origData)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padLength)

	return append(origData, padtext...)
}

func ZeroUnPadding(cipherData []byte) []byte {
	return bytes.TrimFunc(cipherData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func ECBEncrypt(origData, key []byte, padingFun PadingFunc) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//加密（1、先填充数据。 2、再加密）
	origData = padingFun(origData)
	cipherText := make([]byte, len(origData))

	ecbEncrypter := ecb.NewECBEncrypter(block)
	ecbEncrypter.CryptBlocks(cipherText, origData)

	return cipherText, nil
}

func ECBDecrypt(cipheredData, key []byte, unPadingFun PadingFunc) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//解密（1、先解密。 2、再去除填充数据）
	ecbDecrypter := ecb.NewECBDencrypter(block)

	plainText := make([]byte, len(cipheredData))
	ecbDecrypter.CryptBlocks(plainText, cipheredData)

	return unPadingFun(plainText), nil
}
