package ecb

import (
	"crypto/cipher"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) *ecbEncrypter {
	e := &ecbEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
	return e
}

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDencrypter(b cipher.Block) *ecbDecrypter {
	d := &ecbDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
	return d
}

func (d *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		d.b.Decrypt(dst, src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}
