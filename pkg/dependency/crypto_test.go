package dependency

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

func TestDecryptWithBase64(t *testing.T) {
	block, err := aes.NewCipher([]byte("12345678901234567890123456789012")) // AES128=16bytes, AES192=24bytes, AES256=32bytes
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		plainText string
		encoder   func(block *cipher.Block, input string) (string, error)
		want      string
		wantErr   bool
	}{
		{
			name:      "OK",
			plainText: "plain text",
			encoder: func(block *cipher.Block, input string) (string, error) {
				encrypted, err := encrypt(block, input)
				if err != nil {
					return "", err
				}
				return base64.RawStdEncoding.EncodeToString(encrypted), nil
			},
			want: "plain text",
		},
		{
			name:      "NG failed to decode base64",
			plainText: "plain text!",
			encoder: func(block *cipher.Block, input string) (string, error) {
				return "not base64", nil
			},
			wantErr: true,
		},
		{
			name: "NG failed to decrypt",
			encoder: func(block *cipher.Block, input string) (string, error) {
				return "", nil
			},
			plainText: "plain text",
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input, err := c.encoder(&block, c.plainText)
			if err != nil {
				t.Fatalf("failed to encrypt err: %v", err)
			}
			got, err := decryptWithBase64(&block, input)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}

			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}
		})
	}
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
