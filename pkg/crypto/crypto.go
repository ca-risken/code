package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func DecryptWithBase64(block *cipher.Block, encrypted string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	decrypted := decrypt(block, decoded)
	if len(decrypted) < 1 {
		return "", nil
	}

	// Unpadding
	padSize := int(decrypted[len(decrypted)-1])
	return string(decrypted[:len(decrypted)-padSize]), nil
}

func decrypt(block *cipher.Block, encrypted []byte) []byte {
	if len(encrypted) < aes.BlockSize {
		return []byte("")
	}
	iv := encrypted[:aes.BlockSize] // Get Initial Vector form first head block.
	decrypted := make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter := cipher.NewCBCDecrypter(*block, iv)
	decrypter.CryptBlocks(decrypted, encrypted[aes.BlockSize:])
	return decrypted
}
