package auth

import (
	"errors"
	"fmt"
	"strings"
)

type KeySchema struct {
	ID             string
	HashedPassword *string
	UserID         string
}

type UserSchema struct {
	ID string
	DatabaseUserAttributes
}

type SessionSchema struct {
	ID            string
	ActiveExpires int64
	IdleExpires   int64
	UserID        string
	DatabaseSessionAttributes
}

type DatabaseUserAttributes struct{}
type DatabaseSessionAttributes struct{}

func CreateKeyId(providerId, providerUserId string) (string, error) {
	if strings.Contains(providerId, ":") {
		return "", errors.New("provider id must not include any colons (:)")
	}
	return fmt.Sprintf("%s:%s", providerId, providerUserId), nil
}
