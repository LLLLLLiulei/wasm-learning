package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"syscall/js"
)

type UserSecretInfo struct {
	CompanyID      string            `json:"companyID"`
	GUID           string            `json:"GUID"`
	UserName       string            `json:"userName"`
	PublicAESKey   string            `json:"publicAESKey"`
	PrivateKey     string            `json:"privateKey"`
	UserPublicKeys map[string]string `json:"userPublicKeys"`
}

func decryptFileWithAESKey(in io.Reader, key string) (io.ReadCloser, error) {
	keyLen := base64.StdEncoding.DecodedLen(len(key)) - 1
	keyBytes := make([]byte, keyLen)
	_, err := base64.StdEncoding.Decode(keyBytes, []byte(key))
	if err != nil {
		return nil, err
	}
	r, err := AesECBDecryptFile(in, keyBytes)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func parseSecretPackageContent(fileBytes []byte) (*UserSecretInfo, error) {
	reader, _ := gzip.NewReader(bytes.NewReader(fileBytes))
	defer reader.Close()
	bytes, _ := ioutil.ReadAll(reader)
	fmt.Println(string(bytes[:]))

	secretInfo := &UserSecretInfo{}
	err := json.Unmarshal(bytes, secretInfo)
	if err != nil {
		return nil, err
	}
	return secretInfo, nil
}

func parseKeysFileContent(fileBytes []byte) (map[string]string, error) {
	r, err := gzip.NewReader(bytes.NewReader(fileBytes))
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	userKeysMap := make(map[string]string)
	json.Unmarshal(bytes, &userKeysMap)
	return userKeysMap, nil
}

func parseAesKeyFromKeysFile(keysFileBytes []byte, userName, userPrivateKey string) (string, error) {
	keysFileContent, _ := parseKeysFileContent(keysFileBytes)
	encryptedKey := keysFileContent[userName]
	decodedLen := base64.StdEncoding.DecodedLen(len(encryptedKey))
	encryptedKeyBytes := make([]byte, decodedLen-1)
	base64.StdEncoding.Decode(encryptedKeyBytes, []byte(encryptedKey))
	decryptedKey, err := RsaDecrypt(encryptedKeyBytes, userPrivateKey)

	return string(decryptedKey), err
}

var decryptFileBytes []byte

func DecrptyFile(this js.Value, args []js.Value) interface{} {
	encryptType := args[0]
	fileUint8Array := args[1]
	secretPackageUint8Array := args[2]
	keysFileUint8Array := args[3]

	fmt.Println(args)
	fmt.Println(secretPackageUint8Array.Length())
	fmt.Println(fileUint8Array.Length())
	fmt.Println(keysFileUint8Array.Length())

	secretPackageBytes := make([]byte, secretPackageUint8Array.Length())
	res := js.CopyBytesToGo(secretPackageBytes, secretPackageUint8Array)
	fmt.Println("secretPackageBytes", res)

	fileBytes := make([]byte, fileUint8Array.Length())
	res = js.CopyBytesToGo(fileBytes, fileUint8Array)
	fmt.Println("fileUint8Array", res)

	secretPackage, err := parseSecretPackageContent(secretPackageBytes)
	fmt.Println("parseSecretPackageContent", err)
	userPrivateKey := secretPackage.PrivateKey
	aesKey := secretPackage.PublicAESKey
	userName := secretPackage.UserName

	isRsa := encryptType.String() == "RSA"
	if isRsa {
		keysFileBytes := make([]byte, keysFileUint8Array.Length())
		js.CopyBytesToGo(keysFileBytes, keysFileUint8Array)

		decryptedKey, _ := parseAesKeyFromKeysFile(keysFileBytes, userName, userPrivateKey)
		aesKey = string(decryptedKey)
		fmt.Println("decryptedKey", aesKey)
	}

	fileReader, err := decryptFileWithAESKey(bytes.NewReader(fileBytes), aesKey)
	if err != nil {
		return map[string]interface{}{
			"message": "fail",
			"status":  0,
		}
	} else {
		decryptFileBytes, _ = ioutil.ReadAll(fileReader)
		return map[string]interface{}{
			"message":    "success",
			"status":     1,
			"byteLength": len(decryptFileBytes),
		}
	}
}

func CopyDecryptFileBytes(this js.Value, args []js.Value) interface{} {
	if decryptFileBytes == nil {
		return map[string]interface{}{
			"message": "fail",
			"status":  0,
		}
	}
	fmt.Println(string(decryptFileBytes))

	res := js.CopyBytesToJS(args[0], decryptFileBytes)
	fmt.Println("CopyDecryptFileBytes", res)
	decryptFileBytes = nil
	return map[string]interface{}{
		"message": "success",
		"status":  1,
	}
}

func main() {
	js.Global().Set("__decrptyFile", js.FuncOf(DecrptyFile))
	js.Global().Set("__copyDecryptFileBytes", js.FuncOf(CopyDecryptFileBytes))

	<-make(chan bool)
}
