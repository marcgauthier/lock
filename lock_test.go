package main

import (
	"math/rand"
	"strconv"
	"testing"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func TestEncryption(t *testing.T) {

	rand.Seed(time.Now().UnixNano())

	if _, err := EncryptMessage("", "hello"); err == nil {
		t.Errorf("AES encryption no key should generate an error")
	}

	for i := 1; i < 100; i++ {

		key := RandStringRunes(i)

		s := RandStringRunes(i * 10)

		enc, _ := EncryptMessage(key, s)
		dec, _ := DecryptMessage(key, enc)

		if string(dec) != s {
			t.Errorf("AES encryption " + strconv.Itoa(i) + " " + key)
		}
	}

}

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

