package auth

import (
	"errors"
	"log"
	"os"
	"strings"
	"time"
)

type SessionState int

const (
	StateIdle SessionState = iota
	StateActive
)

type Session struct {
	User                  User
	SessionId             string
	ActivePeriodExpiresAt *time.Time
	IdlePeriodExpiresAt   *time.Time
	State                 SessionState
	Fresh                 bool
	SessionAttributes     map[string]interface{}
}

type Key struct {
	UserId          string
	ProviderId      string
	ProviderUserId  string
	PasswordDefined bool
}

type Env int

const (
	ENV_DEVELOPMENT Env = iota
	ENV_PRODUCTION
)

type User struct {
	UserId         string
	UserAttributes map[string]interface{}
}

type GetUserAttributesFunc func(databaseUser UserSchema) map[string]interface{}
type GetSessionAttributesFunc func(databaseSession SessionSchema) map[string]interface{}
type Configuration struct {
	Adapter              Adapter
	Env                  Env // Assuming Env is defined elsewhere
	Middleware           Middleware
	CSRFProtection       CSRFProtection
	SessionExpiresIn     *SessionExpires
	SessionCookie        SessionCookieConfiguration
	GetSessionAttributes GetSessionAttributesFunc
	GetUserAttributes    GetUserAttributesFunc
	PasswordHash         PasswordHash
	Experimental         Experimental
}

type Middleware func(context MiddlewareContext) MiddlewareRequestContext

type MiddlewareContext struct {
	Args              []interface{}
	Env               Env
	SessionCookieName string
}

type MiddlewareRequestContext struct {
	SessionCookie string
	Request       MiddlewareRequest
	SetCookie     func(cookie Cookie)
}

type MiddlewareRequest struct {
	Method              string
	URL                 string
	Headers             Headers
	StoredSessionCookie string
}

type Headers struct {
	Origin        string
	Cookie        string
	Authorization string
}

type CSRFProtection struct {
	Host              string
	HostHeader        string
	AllowedSubDomains []string
}

type Auth struct {
	Adapter              Adapter
	SessionCookieConfig  SessionCookieConfiguration
	SessionExpiresIn     SessionExpires
	CsrfProtection       CSRFProtection
	Env                  Env
	PasswordHash         PasswordHash
	Middleware           Middleware
	Experimental         Experimental
	GetUserAttributes    GetUserAttributesFunc
	GetSessionAttributes GetSessionAttributesFunc
}

type SessionExpires struct {
	ActivePeriod int
	IdlePeriod   int
}

type PasswordHash struct {
	generate func(s string) string
	validate func(s string, hash string) bool
}

type Experimental struct {
	debugMode bool
}

func validateConfiguration(config Configuration) error {
	if config.Adapter == nil {
		err := "Adapter is not defined in configuration ('config.Adapter')"
		log.Println(err)
		return errors.New(err)
	}
	return nil
}

func NewAuth(config Configuration) (*Auth, error) {
	err := validateConfiguration(config)
	if err != nil {
		log.Fatal("Configuration validation failed:", err)
		os.Exit(1)
	}

	auth := &Auth{
		Adapter:              config.Adapter,
		SessionCookieConfig:  config.SessionCookie,
		SessionExpiresIn:     getSessionExpires(config),
		CsrfProtection:       config.CSRFProtection,
		Env:                  config.Env,
		PasswordHash:         config.PasswordHash,
		Middleware:           config.Middleware,
		Experimental:         config.Experimental,
		GetUserAttributes:    config.GetUserAttributes,
		GetSessionAttributes: config.GetSessionAttributes,
	}

	if auth.GetUserAttributes == nil {
		auth.GetUserAttributes = defaultUserAttributeTransform
	}

	if auth.GetSessionAttributes == nil {
		auth.GetSessionAttributes = defaultSessionAttributeTransform
	}

	return auth, nil
}

func getSessionExpires(config Configuration) SessionExpires {
	activePeriod := 24 * time.Hour
	idlePeriod := 14 * 24 * time.Hour

	if config.SessionExpiresIn != nil {
		if config.SessionExpiresIn.ActivePeriod != 0 {
			activePeriod = time.Duration(config.SessionExpiresIn.ActivePeriod) * time.Millisecond
		}
		if config.SessionExpiresIn.IdlePeriod != 0 {
			idlePeriod = time.Duration(config.SessionExpiresIn.IdlePeriod) * time.Millisecond
		}
	}
	return SessionExpires{
		ActivePeriod: int(activePeriod),
		IdlePeriod:   int(idlePeriod),
	}
}

func defaultUserAttributeTransform(user UserSchema) map[string]interface{} {
	return make(map[string]interface{})
}

func defaultSessionAttributeTransform(session SessionSchema) map[string]interface{} {
	return make(map[string]interface{})
}

func (a *Auth) TransformDatabaseUser(databaseUser UserSchema) User {
	attributes := a.GetUserAttributes(databaseUser)
	return User{
		UserId:         databaseUser.ID,
		UserAttributes: attributes,
	}
}

func (a *Auth) TransformDatabaseKey(databaseKey KeySchema) Key {
	segments := strings.Split(databaseKey.ID, ":")
	providerId := segments[0]
	providerUserId := strings.Join(segments[1:], ":")

	return Key{
		ProviderId:      providerId,
		ProviderUserId:  providerUserId,
		UserId:          databaseKey.UserID,
		PasswordDefined: databaseKey.HashedPassword != nil,
	}
}

type SessionContext struct {
	User  User
	Fresh bool
}

func (a *Auth) TransformDatabaseSession(databaseSession SessionSchema, context SessionContext) Session {
	attributes := a.GetSessionAttributes(databaseSession)
	active := isWithinExpiration(databaseSession.ActiveExpires)

	activePeriodExpiresAt := time.Unix(0, databaseSession.ActiveExpires*int64(time.Millisecond))
	idlePeriodExpiresAt := time.Unix(0, databaseSession.IdleExpires*int64(time.Millisecond))
	var state SessionState
	if active {
		state = StateActive
	} else {
		state = StateIdle
	}

	return Session{
		User:                  context.User,
		SessionId:             databaseSession.ID,
		SessionAttributes:     attributes,
		ActivePeriodExpiresAt: &activePeriodExpiresAt,
		IdlePeriodExpiresAt:   &idlePeriodExpiresAt,
		State:                 state,
		Fresh:                 context.Fresh,
	}
}

func isWithinExpiration(expiration int64) bool {
	return time.Now().Before(time.Unix(0, expiration*int64(time.Millisecond)))
}
