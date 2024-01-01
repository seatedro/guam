package auth

import (
	"errors"
	"log"
	"os"
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

type Configuration struct {
	Adapter              Adapter
	Env                  Env // Assuming Env is defined elsewhere
	Middleware           Middleware
	CSRFProtection       CSRFProtection
	SessionExpiresIn     SessionExpires
	SessionCookie        SessionCookieConfiguration
	GetSessionAttributes func(SessionSchema) map[string]interface{}
	GetUserAttributes    func(UserSchema) map[string]interface{}
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
	adapter             Adapter
	sessionCookieConfig SessionCookieConfiguration
	sessionExpiresIn    SessionExpires
	csrfProtection      CSRFProtection
	env                 Env
	passwordHash        PasswordHash
	middleware          Middleware
	experimental        Experimental
	// other fields
}

type SessionExpires struct {
	activePeriod int
	idlewPeriod  int
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

func NewAuth(config Configuration) *Auth {
	err := validateConfiguration(config)
	if err != nil {
		log.Fatal("Configuration validation failed:", err)
		os.Exit(1)
	}

	return &Auth{
		adapter:             config.Adapter,
		sessionCookieConfig: config.SessionCookie,
		sessionExpiresIn:    config.SessionExpiresIn,
		csrfProtection:      config.CSRFProtection,
		env:                 config.Env,
		passwordHash:        config.PasswordHash,
		middleware:          config.Middleware,
		experimental:        config.Experimental,
	}
}
