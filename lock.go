package lock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func EncryptMessage(secret string, message string) (string, error) {

	if len(secret) <= 0 {
		return message, errors.New("Key must be provided")
	}

	if len(secret) != 16 {
		secret = makeStringSpecificLength(secret, 16, "0")
	}

	key := []byte(secret)

	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(secret string, message string) (string, error) {

	if len(secret) <= 0 {
		return message, errors.New("Key must be provided")
	}

	if len(secret) != 16 {
		secret = makeStringSpecificLength(secret, 16, "0")
	}

	key := []byte(secret)
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func makeStringSpecificLength(s string, length int, ch string) string {

	for {
		if len(s) < length {
			s += ch
		} else {
			break
		}
	}

	return s[:length]

}

