package utils

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"guam/scrypt"
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

func GenerateScryptHash(s string) string {
	salt, err := GenerateRandomString(16, "")
	if err != nil {
		panic(err)
	}

	key := hashWithScrypt(norm.NFKC.String(s), salt, 16)

	return fmt.Sprintf("s2:%s:%s", salt, key)
}

func hashWithScrypt(s, salt string, blockSize int) string {
	options := scrypt.ScryptOptions{
		N:     16384,
		R:     blockSize,
		P:     1,
		DkLen: 64,
	}
	key, err := scrypt.Scrypt([]byte(s), []byte(salt), options)
	if err != nil {
		panic(err)
	}

	return ConvertByteSliceToHex(key)
}

func ConvertByteSliceToHex(arr []byte) string {
	hexStr := ""
	for _, b := range arr {
		hexStr += fmt.Sprintf("%02x", b)
	}

	return hexStr
}
