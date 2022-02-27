package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	publicKeyPrefix  = "-----BEGIN PUBLIC KEY-----"
	publicKeySuffix  = "-----END PUBLIC KEY-----"
	privateKeyPrefix = "-----BEGIN PRIVATE KEY-----"
	privateKeySuffix = "-----END PRIVATE KEY-----"
)

func RsaEncrypt(origData []byte, publicKey string) ([]byte, error) {
	if !strings.HasPrefix(publicKey, publicKeyPrefix) {
		publicKey = fmt.Sprintf("%s\n%s\n%s", publicKeyPrefix, publicKey, publicKeySuffix)
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, origData, []byte(""))
}

func RsaDecrypt(ciphertext []byte, privateKey string) ([]byte, error) {
	if !strings.HasPrefix(privateKey, privateKeyPrefix) {
		privateKey = fmt.Sprintf("%s\n%s\n%s", privateKeyPrefix, privateKey, privateKeySuffix)
	}

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("private key error")
	}
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	fmt.Println(err)
	if err != nil {
		return nil, err
	}
	priv := parseResult.(*rsa.PrivateKey)
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, []byte(""))
}
