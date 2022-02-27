package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type PaddingType string

const (
	PKCS5_PADDING PaddingType = "PKCS5"
	PKCS7_PADDING PaddingType = "PKCS7"
	ZEROS_PADDING PaddingType = "ZEROS"
)

func Padding(paddingType PaddingType, src []byte, blockSize int) []byte {
	switch paddingType {
	case PKCS5_PADDING:
		src = PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		src = PKCS7Padding(src, blockSize)
	}
	return src
}

func UnPadding(paddingType PaddingType, src []byte) []byte {
	switch paddingType {
	case PKCS5_PADDING:
		src = PKCS5Unpadding(src)
	case PKCS7_PADDING:
		src = PKCS7UnPadding(src)
	}
	return src
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	return PKCS7Padding(src, blockSize)
}

func PKCS5Unpadding(src []byte) []byte {
	return PKCS7UnPadding(src)
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func ECBEncrypt(block cipher.Block, src []byte, padding PaddingType) ([]byte, error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))

	ecb := NewECBEncrypter(block)
	ecb.CryptBlocks(encryptData, src)

	return encryptData, nil
}

func ECBDecrypt(block cipher.Block, src []byte, padding PaddingType) ([]byte, error) {
	dst := make([]byte, len(src))

	mode := NewECBDecrypter(block)
	mode.CryptBlocks(dst, src)

	dst = UnPadding(padding, dst)

	return dst, nil
}

type ecb struct {
	block     cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		block:     b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (encrypter *ecbEncrypter) BlockSize() int {
	return encrypter.blockSize
}

func (encrypter *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%encrypter.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		encrypter.block.Encrypt(dst, src[:encrypter.blockSize])
		src = src[encrypter.blockSize:]
		dst = dst[encrypter.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (decrypter *ecbDecrypter) BlockSize() int {
	return decrypter.blockSize
}

func (decrypter *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%decrypter.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		decrypter.block.Decrypt(dst, src[:decrypter.blockSize])
		src = src[decrypter.blockSize:]
		dst = dst[decrypter.blockSize:]
	}

}

func AesECBEncrypt(src, key []byte, padding PaddingType) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, padding)
}

func AesECBDecrypt(src, key []byte, padding PaddingType) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBDecrypt(block, src, padding)
}

func AesECBDecryptFile(in io.Reader, key []byte) (io.ReadCloser, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	reader, writer := io.Pipe()

	go func() {
		blockSize := block.BlockSize()
		bufSize := blockSize * 2 * 1024
		buf := make([]byte, bufSize)
		dst := make([]byte, 0)
		tmp := make([]byte, 0)
		count := 0

		for {
			nr, er := in.Read(buf)
			count += nr

			if nr > 0 {
				tmp = append(tmp, buf[0:nr]...)
			}

			if len(tmp) >= blockSize {
				maxLen := len(tmp) - len(tmp)%blockSize
				src := tmp[:maxLen]

				part := make([]byte, maxLen)
				temp := part[:]
				for len(src) > 0 {
					block.Decrypt(temp, src)
					src = src[blockSize:]
					temp = temp[blockSize:]
				}
				dst = append(dst, part...)
				tmp = tmp[maxLen:]
			}

			if er != nil {
				fmt.Println(er)
				if er != io.EOF {
					writer.CloseWithError(er)
				} else {
					if len(dst) > 0 {
						length := len(dst)
						unpadding := int(dst[length-1])
						dst = dst[:(length - unpadding)]
						writer.Write(dst)
					}
					writer.Close()
				}
				break
			} else {
				if len(dst) > bufSize {
					part := dst[:bufSize]
					writer.Write(part)
					dst = dst[bufSize:]
				}
			}
		}
	}()

	return reader, nil
}

func AesECBEncryptFile(in io.Reader, key []byte) (io.ReadCloser, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()

	go func() {
		blockSize := block.BlockSize()
		bufSize := blockSize * 2 * 1024
		buf := make([]byte, bufSize)
		dst := make([]byte, 0)
		tmp := make([]byte, 0)
		count := 0

		for {
			nr, er := in.Read(buf)
			count += nr

			if nr > 0 {
				tmp = append(tmp, buf[0:nr]...)
			}

			if len(tmp) >= blockSize {
				maxLen := len(tmp) - len(tmp)%blockSize
				src := tmp[:maxLen]

				part := make([]byte, maxLen)
				temp := part[:]
				for len(src) > 0 {
					block.Encrypt(temp, src)
					src = src[blockSize:]
					temp = temp[blockSize:]
				}
				dst = append(dst, part...)
				tmp = tmp[maxLen:]
			}

			if er != nil {
				if er != io.EOF {
					writer.CloseWithError(er)
				} else {
					if len(dst) > 0 {
						padding := blockSize - len(dst)%blockSize
						padtext := bytes.Repeat([]byte{byte(padding)}, padding)
						dst = append(dst, padtext...)
						writer.Write(dst)

					}
					writer.Close()
				}
				break
			} else {
				if len(dst) > bufSize {
					part := dst[:bufSize]
					writer.Write(part)
					dst = dst[bufSize:]
				}
			}
		}
	}()

	return reader, nil
}

func GenerateAESKey() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
