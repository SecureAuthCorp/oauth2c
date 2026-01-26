package oauth2

import (
	"crypto/rand"
)

var letter = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)

	for i := range b {
		b[i] = letter[b[i]%byte(len(letter))]
	}

	return string(b)
}
