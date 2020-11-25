package common

import (
	"crypto/aes"
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
			encrypted, err := EncryptWithBase64(&block, c.input)
			if c.wantEncError && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantEncError && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}

			decrypted, err := DecryptWithBase64(&block, encrypted)
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
