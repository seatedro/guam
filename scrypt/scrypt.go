package scrypt

import "golang.org/x/crypto/scrypt"

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
