package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	block, err := aes.NewCipher([]byte("12345678901234567890123456789012")) // AES128=16bytes, AES192=24bytes, AES256=32bytes
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		input        string
		want         string
		wantEncError bool
		wantDecError bool
	}{
		{
			name:  "OK",
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "OK (black))",
			input: "",
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encrypted, err := encryptWithBase64(&block, c.input)
			if c.wantEncError && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantEncError && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}

			decrypted, err := decryptWithBase64(&block, encrypted)
			if c.wantDecError && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantDecError && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}

			if !reflect.DeepEqual(c.want, decrypted) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, decrypted)
			}
		})
	}
}

func encryptWithBase64(block *cipher.Block, plainText string) (string, error) {
	buf, err := encrypt(block, plainText)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

func encrypt(block *cipher.Block, plainText string) ([]byte, error) {
	padSize := aes.BlockSize - (len(plainText) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	paddedText := append([]byte(plainText), pad...)

	encrypted := make([]byte, aes.BlockSize+len(paddedText))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return encrypted, err
	}
	encrypter := cipher.NewCBCEncrypter(*block, iv)
	encrypter.CryptBlocks(encrypted[aes.BlockSize:], []byte(paddedText))
	return encrypted, nil
}
