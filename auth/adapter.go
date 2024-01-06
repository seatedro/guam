package auth

type Adapter interface {
	UserAdapter
	SessionAdapter
}

type AdapterWithGetter interface {
	Adapter
	GetSessionAndUser(sessionId string) (*SessionSchema, *UserJoinSessionSchema, error)
}

type UserAdapter interface {
	GetUser(userId string) (*UserSchema, error)
	SetUser(user UserSchema, key *KeySchema) error
	UpdateUser(userId string, partialUser map[string]any) error
	DeleteUser(userId string) error
	GetKey(keyId string) (*KeySchema, error)
	GetKeysByUserId(userId string) ([]KeySchema, error)
	SetKey(key KeySchema) error
	UpdateKey(keyId string, partialKey map[string]any) error
	DeleteKey(keyId string) error
	DeleteKeysByUserId(userId string) error
}

type SessionAdapter interface {
	GetSession(sessionId string) (*SessionSchema, error)
	GetSessionsByUserId(userId string) ([]SessionSchema, error)
	SetSession(session SessionSchema) error
	UpdateSession(sessionId string, partialSession map[string]any) error
	DeleteSession(sessionId string) error
	DeleteSessionsByUserId(userId string) error
}

type (
	AdapterInitializer          func(errorConstructor GuamErrorConstructor) Adapter
	AdapterCompositeInitializer struct {
		User    AdapterInitializer
		Session AdapterInitializer
	}
)
type GuamErrorConstructor func(ErrorMessage, *string) *GuamError

type CombinedAdapter struct {
	UserAdapter
	SessionAdapter
}

func CreateAdapter(adapter interface{}) Adapter {
	// Check if adapter is a single AdapterInitializer
	if init, ok := adapter.(AdapterInitializer); ok {
		return init(NewGuamError)
	}

	// Check if adapter is a struct with user and session initializers
	if compositeInit, ok := adapter.(AdapterCompositeInitializer); ok {
		userAdapter := compositeInit.User(NewGuamError)
		sessionAdapter := compositeInit.Session(NewGuamError)

		return &CombinedAdapter{
			UserAdapter:    userAdapter,
			SessionAdapter: sessionAdapter,
		}
	}

	return nil
}

func (ca *CombinedAdapter) GetSessionAndUser(
	sessionId string,
) (*SessionSchema, *UserSchema, error) {
	return nil, nil, nil
}
