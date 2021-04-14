package rsautil

import (
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type parsePublicKey func([]byte) (*rsa.PublicKey, error)
type parsePrivateKey func([]byte) (*rsa.PrivateKey, error)

//encrypt decrypt func with publicKey or privateKey
type cryptWithPub func([]byte, *rsa.PublicKey) ([]byte, error)
type cryptWithPri func([]byte, *rsa.PrivateKey) ([]byte, error)

type Config struct {
	ParsePublicKey     parsePublicKey
	ParsePrivateKey    parsePrivateKey
	EncryptWithPublic  cryptWithPub
	EncryptWithPrivate cryptWithPri
	DecryptWithPub     cryptWithPub
	DecryptWithPrivate cryptWithPri

	CryptSub bool
	SubStep  int
}

//default rsa encrypt
func Encrypt(data []byte, key []byte, cfg *Config) ([]byte, error) {
	var buf []byte
	if cfg == nil {
		cfg = &Config{
			ParsePublicKey:    ParsePKIXPublicKey,
			EncryptWithPublic: EncryptPKCS1v15,
		}
	}
	if cfg.ParsePublicKey == nil {
		return buf, errors.New("ParsePublicKey cannot be nil")
	}
	if cfg.EncryptWithPublic == nil {
		return buf, errors.New("EncryptwithPub cannot be nil")
	}

	publicKey, err := cfg.ParsePublicKey(key)
	if err != nil {
		return buf, err
	}

	if cfg.CryptSub {
		//if cfg.SubStep <= 0 {
		//	err = errors.New("RSAConfig.SubStep should be set")
		//	return buf, err
		//}

		n := len(data)
		for i := 0; i < n; i += cfg.SubStep {
			r := i + cfg.SubStep
			if r > n {
				r = n
			}

			b, err := cfg.EncryptWithPublic(data[i:r], publicKey)
			if err != nil {
				return buf, err
			}
			buf = append(buf, b...)
		}
		return buf, nil
	}

	return cfg.EncryptWithPublic([]byte(data), publicKey)
}

//default rsa decrypt
func Decrypt(data []byte, key []byte, cfg *Config) ([]byte, error) {
	var buf []byte
	if cfg == nil {
		cfg = &Config{
			ParsePrivateKey:    ParsePKCS1PrivateKey,
			DecryptWithPrivate: DecryptPKCS1v15,
		}
	}
	if cfg.ParsePrivateKey == nil {
		return buf, errors.New("ParsePrivateKey cannot be nil")
	}
	if cfg.DecryptWithPrivate == nil {
		return buf, errors.New("DecryptWithPrivate cannot be nil")
	}

	privateKey, err := cfg.ParsePrivateKey(key)
	if err != nil {
		return buf, err
	}

	if cfg.CryptSub {
		n := len(data)
		for i := 0; i < n; i += cfg.SubStep {
			r := i + cfg.SubStep
			if r > n {
				r = n
			}

			b, err := cfg.DecryptWithPrivate(data[i:r], privateKey)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
		}
		return buf, nil
	}

	return cfg.DecryptWithPrivate(data, privateKey)
}

func ParsePKIXPublicKey(publickKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publickKey)
	if block == nil {
		return nil, errors.New("decode public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubInterface.(*rsa.PublicKey), nil
}

func ParsePKCS1PublicKey(publickKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publickKey))
	if block == nil {
		return nil, errors.New("decode public key error")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func EncryptPKCS1v15(data []byte, key *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, key, []byte(data))
}

func ParsePKCS1PrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		panic("block is nil")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return priv, err
}

func ParsePKCS8PrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("block is nil")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey := priv.(*rsa.PrivateKey)
	return privKey, nil
}

func DecryptPKCS1v15(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, key, data)
}

//PKCS方式计算sign
func SignByPKCS1v15(data []byte, priKey *rsa.PrivateKey, h crypto.Hash) ([]byte, error) {
	hash := h.New()
	hash.Write(data)

	return rsa.SignPKCS1v15(rand.Reader, priKey, h, hash.Sum(nil))
}

func VerifySignByPKCS1v15(originalData, signData []byte, pubKey *rsa.PublicKey, h crypto.Hash) bool {
	hash := h.New()
	hash.Write(originalData)

	return rsa.VerifyPKCS1v15(pubKey, h, hash.Sum(nil), signData) == nil
}

//PSS方式计算sign（加盐哈希）
func SignByPSS(data []byte, priKey *rsa.PrivateKey, h crypto.Hash) ([]byte, error) {
	hash := h.New()
	hash.Write(data)
	pssOption := &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       0,
	}

	return rsa.SignPSS(rand.Reader, priKey, h, hash.Sum(nil), pssOption)
}

func VerifySignByPSS(originalData, signData []byte, pubKey *rsa.PublicKey, h crypto.Hash) bool {
	hash := h.New()
	hash.Write(originalData)
	pssOption := &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       0,
	}

	return rsa.VerifyPSS(pubKey, h, hash.Sum(nil), signData, pssOption) == nil
}
