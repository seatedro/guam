package auth

import (
	"errors"
)

type Adapter interface {
	GetSessionAndUser(sessionId string) (*SessionSchema, *UserSchema, error)
	UserAdapter
	SessionAdapter
}

type UserAdapter interface {
	GetUser(userId string) (*UserSchema, error)
	SetUser(user UserSchema, key *KeySchema) error
	UpdateUser(user UserSchema, partialUser UserSchema) error
	DeleteUser(user UserSchema) error
}

type SessionAdapter interface {
	GetSession(sessionId string) (*SessionSchema, error)
	GetSessionsByUserId(userId string) ([]SessionSchema, error)
	SetSession(session SessionSchema) error
}

type AdapterInitializer func(errorConstructor GuamErrorConstructor) Adapter
type AdapterCompositeInitializer struct {
	User    AdapterInitializer
	Session AdapterInitializer
}
type GuamErrorConstructor func() error

type CombinedAdapter struct {
	UserAdapter
	SessionAdapter
}

func CreateAdapter(adapter interface{}) Adapter {
	// Check if adapter is a single AdapterInitializer
	if init, ok := adapter.(AdapterInitializer); ok {
		return init(GuamError)
	}

	// Check if adapter is a struct with user and session initializers
	if compositeInit, ok := adapter.(AdapterCompositeInitializer); ok {
		userAdapter := compositeInit.User(GuamError)
		sessionAdapter := compositeInit.Session(GuamError)

		return &CombinedAdapter{
			UserAdapter:    userAdapter,
			SessionAdapter: sessionAdapter,
		}
	}
}

func (ca *CombinedAdapter) GetSessionAndUser(sessionId string) (*SessionSchema, *UserSchema, error) {
	return nil, nil, nil
}

func GuamError() error {
	return errors.New("guam error")
}
