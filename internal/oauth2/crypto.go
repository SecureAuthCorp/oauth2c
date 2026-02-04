package oauth2

import (
	"crypto/rand"
)

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func RandomString(n int) string {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}

	return string(b)
}
