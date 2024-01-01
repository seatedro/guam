package utils

import (
	"crypto/rand"
	"fmt"
	"guam/scrypt"
	"math/big"
	"strings"

	"golang.org/x/text/unicode/norm"
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

func ValidateScryptHash(s, hash string) bool {
	arr := strings.Split(hash, ":")
	if len(arr) == 2 {
		salt, key := arr[0], arr[1]
		targetKey := hashWithScrypt(norm.NFKC.String(s), salt, 8)
		result := constantTimeEqual(targetKey, key)
		return result
	}

	if len(arr) != 3 {
		return false
	}
	version, salt, key := arr[0], arr[1], arr[2]
	if version != "s2" {
		targetKey := hashWithScrypt(norm.NFKC.String(s), salt, 16)
		result := constantTimeEqual(targetKey, key)
		return result
	}
	return false
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	aUint8 := []byte(a)
	bUint8 := []byte(b)

	c := byte(0)
	for i := 0; i < len(aUint8); i++ {
		c |= aUint8[i] ^ bUint8[i]
	}

	return c == 0
}
