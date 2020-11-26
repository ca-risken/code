package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// EncryptWithBase64 Encrypt the `plainText` and base64 encoding.
func EncryptWithBase64(block *cipher.Block, plainText string) (string, error) {
	buf, err := Encrypt(block, plainText)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

// Encrypt Encrypt the `plainText`.
func Encrypt(block *cipher.Block, plainText string) ([]byte, error) {
	// PKCS#7 Padding (CBCブロック暗号モードで暗号化したいので、長さが16byteの倍数じゃない場合は末尾をパディングしとく)
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

// DecryptWithBase64 Decrypt the `encrypted` and base64 decoding.
func DecryptWithBase64(block *cipher.Block, encrypted string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	decrypted := Decrypt(block, decoded)

	// Unpadding
	padSize := int(decrypted[len(decrypted)-1])
	return string(decrypted[:len(decrypted)-padSize]), nil
}

// Decrypt Decrypt the `encrypted`.
func Decrypt(block *cipher.Block, encrypted []byte) []byte {
	if len(encrypted) < aes.BlockSize {
		return []byte("")
	}
	iv := encrypted[:aes.BlockSize] // Get Initial Vector form first head block.
	decrypted := make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter := cipher.NewCBCDecrypter(*block, iv)
	decrypter.CryptBlocks(decrypted, encrypted[aes.BlockSize:])
	return decrypted
}
