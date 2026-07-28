package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func DecryptWithBase64(block *cipher.Block, encrypted string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	decrypted, err := decrypt(block, decoded)
	if err != nil {
		return "", err
	}

	// Unpadding
	if len(decrypted) == 0 {
		return "", fmt.Errorf("invalid padding")
	}
	padSize := int(decrypted[len(decrypted)-1])
	if padSize < 1 || padSize > aes.BlockSize || padSize > len(decrypted) {
		return "", fmt.Errorf("invalid padding")
	}
	for _, b := range decrypted[len(decrypted)-padSize:] {
		if int(b) != padSize {
			return "", fmt.Errorf("invalid padding")
		}
	}
	return string(decrypted[:len(decrypted)-padSize]), nil
}

func decrypt(block *cipher.Block, encrypted []byte) ([]byte, error) {
	if len(encrypted) < aes.BlockSize {
		return []byte{}, fmt.Errorf("ciphertext too short")
	}
	if (len(encrypted)-aes.BlockSize)%aes.BlockSize != 0 {
		return []byte{}, fmt.Errorf("invalid ciphertext length")
	}
	iv := encrypted[:aes.BlockSize] // Get Initial Vector form first head block.
	decrypted := make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter := cipher.NewCBCDecrypter(*block, iv)
	decrypter.CryptBlocks(decrypted, encrypted[aes.BlockSize:])
	return decrypted, nil
}
