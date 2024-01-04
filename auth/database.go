package auth

import (
	"errors"
	"fmt"
	"strings"
)

type KeySchema struct {
	ID             string  `db:"id"`
	HashedPassword *string `db:"hashed_password"`
	UserID         string  `db:"user_id"`
}

type UserSchema struct {
	Attributes map[string]interface{}
	ID         string `db:"id"`
}

type SessionSchema struct {
	Attributes    map[string]interface{}
	ID            string `db:"id"`
	UserID        string `db:"user_id"`
	ActiveExpires int64  `db:"active_expires"`
	IdleExpires   int64  `db:"idle_expires"`
}

type UserJoinSessionSchema struct {
	UserSchema
	SessionID string `db:"__session_id"`
}

func CreateKeyId(providerId, providerUserId string) (string, error) {
	if strings.Contains(providerId, ":") {
		return "", errors.New("provider id must not include any colons (:)")
	}
	return fmt.Sprintf("%s:%s", providerId, providerUserId), nil
}
