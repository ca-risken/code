package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func decryptWithBase64(block *cipher.Block, encrypted string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	decrypted, err := decrypt(block, decoded)
	if err != nil {
		return "", err
	}

	// Unpadding
	padSize := int(decrypted[len(decrypted)-1])
	return string(decrypted[:len(decrypted)-padSize]), nil
}

func decrypt(block *cipher.Block, encrypted []byte) ([]byte, error) {
	if len(encrypted) < aes.BlockSize {
		return []byte{}, fmt.Errorf("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize] // Get Initial Vector form first head block.
	decrypted := make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter := cipher.NewCBCDecrypter(*block, iv)
	decrypter.CryptBlocks(decrypted, encrypted[aes.BlockSize:])
	return decrypted, nil
}
