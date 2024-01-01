package utils

import (
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"math/big"
)

const DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyz1234567890"

func GenerateRandomString(length int, alphabet string) (string, error) {
	if alphabet == "" {
		alphabet = DEFAULT_ALPHABET
	}

	var result string
	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		result += string(alphabet[index.Int64()])
	}

	return result, nil
}

type ScryptOptions struct {
	N     int
	R     int
	P     int
	DkLen int
}

func Scrypt(password, salt []byte, options ScryptOptions) ([]byte, error) {
	if options.DkLen == 0 {
		options.DkLen = 32
	}

	key, err := scrypt.Key(password, salt, options.N, options.R, options.P, options.DkLen)
	if err != nil {
		return nil, err
	}

	return key, nil
}
