package auth

import (
	"errors"
	"github.com/rohitp934/guam/utils"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

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
	Env                  Env
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
	PasswordHash         *PasswordHash
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
		logger.Info(err)
		return errors.New(err)
	}
	return nil
}

func NewAuth(config Configuration) (*Auth, error) {
	err := validateConfiguration(config)
	if err != nil {
		logger.Fatal("Configuration validation failed:", err)
		os.Exit(1)
	}

	auth := &Auth{
		Adapter:              config.Adapter,
		SessionCookieConfig:  config.SessionCookie,
		SessionExpiresIn:     getSessionExpires(config),
		CsrfProtection:       config.CSRFProtection,
		Env:                  config.Env,
		PasswordHash:         &config.PasswordHash,
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

	if auth.PasswordHash == nil {
		auth.PasswordHash = &PasswordHash{
			generate: utils.GenerateScryptHash,
			validate: utils.ValidateScryptHash,
		}
	}

	if auth.Experimental.debugMode {
		l, err := zap.NewDevelopment()
		if err != nil {
			logger = zap.NewNop().Sugar()
		}
		logger = l.Sugar()
	} else {
		l, err := zap.NewProduction(zap.IncreaseLevel(zap.ErrorLevel))
		if err != nil {
			logger = zap.NewNop().Sugar()
		}
		logger = l.Sugar()
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

func (a *Auth) TransformDatabaseUser(databaseUser UserSchema) *User {
	attributes := a.GetUserAttributes(databaseUser)
	return &User{
		UserId:         databaseUser.ID,
		UserAttributes: attributes,
	}
}

func (a *Auth) TransformDatabaseKey(databaseKey KeySchema) *Key {
	segments := strings.Split(databaseKey.ID, ":")
	providerId := segments[0]
	providerUserId := strings.Join(segments[1:], ":")

	return &Key{
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

func (a *Auth) TransformDatabaseSession(databaseSession SessionSchema, context SessionContext) *Session {
	attributes := a.GetSessionAttributes(databaseSession)
	active := IsWithinExpiration(databaseSession.ActiveExpires)

	activePeriodExpiresAt := time.Unix(0, databaseSession.ActiveExpires*int64(time.Millisecond))
	idlePeriodExpiresAt := time.Unix(0, databaseSession.IdleExpires*int64(time.Millisecond))
	var state SessionState
	if active {
		state = StateActive
	} else {
		state = StateIdle
	}

	return &Session{
		User:                  context.User,
		SessionId:             databaseSession.ID,
		SessionAttributes:     attributes,
		ActivePeriodExpiresAt: &activePeriodExpiresAt,
		IdlePeriodExpiresAt:   &idlePeriodExpiresAt,
		State:                 state,
		Fresh:                 context.Fresh,
	}
}

func IsWithinExpiration(expiration int64) bool {
	return time.Now().Before(time.Unix(0, expiration*int64(time.Millisecond)))
}

func (a *Auth) getDatabaseUser(userId string) (*UserSchema, error) {
	user, err := a.Adapter.GetUser(userId)
	if err != nil {
		return &UserSchema{}, err
	}
	return user, nil
}

func (a *Auth) getDatabaseSession(sessionId string) (*SessionSchema, error) {
	session, err := a.Adapter.GetSession(sessionId)
	if err != nil {
		return &SessionSchema{}, err
	}
	if !IsValidDatabaseSession(session) {
		logger.Errorf("Session expired at %s", time.Unix(0, session.IdleExpires*int64(time.Millisecond)))
		return &SessionSchema{}, errors.New("AUTH_INVALID_SESSION_ID")
	}
	return session, nil
}

func (a *Auth) getDatabaseSessionAndUser(sessionId string) (*SessionSchema, *UserSchema, error) {
	if ad, ok := a.Adapter.(AdapterWithGetter); ok {
		session, user, err := ad.GetSessionAndUser(sessionId)
		if err != nil {
			return &SessionSchema{}, &UserSchema{}, err
		}
		if !IsValidDatabaseSession(session) {
			logger.Fatalf("Session expired at %s", time.Unix(0, session.IdleExpires*int64(time.Millisecond)))
			return &SessionSchema{}, &UserSchema{}, errors.New("AUTH_INVALID_SESSION_ID")
		}
		return session, user, nil
	}
	session, err := a.getDatabaseSession(sessionId)
	if err != nil {
		return &SessionSchema{}, &UserSchema{}, err
	}
	user, err := a.getDatabaseUser(session.UserID)
	if err != nil {
		return &SessionSchema{}, &UserSchema{}, err
	}

	return session, user, nil
}

func (a *Auth) validateSessionIdArgument(sessionId string) error {
	if sessionId == "" {
		return errors.New("AUTH_INVALID_SESSION_ID")
	}
	return nil
}

func (a *Auth) getNewSessionExpiration(sessionExpiresIn *SessionExpires) (int64, int64) {
	var activePeriod, idlePeriod int
	if sessionExpiresIn != nil {
		activePeriod = sessionExpiresIn.ActivePeriod
		idlePeriod = sessionExpiresIn.IdlePeriod
	} else {
		activePeriod = a.SessionExpiresIn.ActivePeriod
		idlePeriod = a.SessionExpiresIn.IdlePeriod
	}
	activeExpires := time.Now().Add(time.Duration(activePeriod)*time.Millisecond).UnixNano() / int64(time.Millisecond)
	idleExpires := time.Now().Add(time.Duration(idlePeriod)*time.Millisecond).UnixNano() / int64(time.Millisecond)
	return activeExpires, idleExpires
}

func (a *Auth) GetUser(userId string) (*User, error) {
	userSchema, err := a.getDatabaseUser(userId)
	if err != nil {
		return nil, err
	}
	user := a.TransformDatabaseUser(*userSchema)
	return user, nil
}

type CreateUserKey struct {
	providerId     string
	providerUserId string
	password       *string
}
type CreateUserOptions struct {
	userId     *string
	key        *CreateUserKey
	attributes *DatabaseUserAttributes
}

func (a *Auth) CreateUser(options CreateUserOptions) *User {
	var userId string
	if options.userId != nil {
		userId = *options.userId
	} else {
		userId = utils.GenerateRandomString(15, "")
	}

	var userAttributes DatabaseUserAttributes
	if options.attributes != nil {
		userAttributes = *options.attributes
	} else {
		userAttributes = DatabaseUserAttributes{}
	}

	databaseUser := UserSchema{
		ID:                     userId,
		DatabaseUserAttributes: userAttributes,
	}

	if options.key == nil {
		err := a.Adapter.SetUser(databaseUser, nil)
		if err != nil {
			logger.Errorf("Error creating user: %s", err)
			return nil
		}
		return a.TransformDatabaseUser(databaseUser)
	}

	keyId, err := CreateKeyId(options.key.providerId, options.key.providerUserId)
	if err != nil {
		logger.Errorf("Error creating user: %s", err)
		return nil
	}

	password := options.key.password
	var hashedPassword *string
	if password != nil {
		hash := a.PasswordHash.generate(*password)
		hashedPassword = &hash
	} else {
		hashedPassword = nil
	}

	a.Adapter.SetUser(databaseUser, &KeySchema{
		ID:             keyId,
		HashedPassword: hashedPassword,
		UserID:         userId,
	})
	return a.TransformDatabaseUser(databaseUser)
}

func (a *Auth) UpdateUserAttributes(userId string, attributes *DatabaseUserAttributes) (*User, error) {
	a.Adapter.UpdateUser(userId, attributes)
	return a.GetUser(userId)
}

func (a *Auth) DeleteUser(userId string) error {
	err := a.Adapter.DeleteSessionsByUserId(userId)
	if err != nil {
		return err
	}
	err = a.Adapter.DeleteKeysByUserId(userId)
	if err != nil {
		return err
	}
	err = a.Adapter.DeleteUser(userId)
	if err != nil {
		return err
	}
	return nil
}

func (a *Auth) UseKey(providerId, providerUserId string, password *string) (*Key, error) {
	keyId, err := CreateKeyId(providerId, providerUserId)
	if err != nil {
		return nil, err
	}
	databaseKey, err := a.Adapter.GetKey(keyId)
	if err != nil {
		logger.Errorf("Key not found", keyId)
		return nil, errors.New("AUTH_INVALID_KEY_ID")
	}

	hashedPassword := databaseKey.HashedPassword
	if hashedPassword != nil {
		logger.Info("Key includes password")
		if password == nil {
			logger.Error("Key password not provided", keyId)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}

		validPassword := a.PasswordHash.validate(*password, *hashedPassword)
		if !validPassword {
			logger.Error("Incorrect key password", *password)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}
		logger.Info("Validated key password")
	} else {
		if password != nil {
			logger.Error("Incorrect key password", *password)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}
		logger.Info("No password included in key")
	}
	logger.Info("Validated key", keyId)
	return a.TransformDatabaseKey(*databaseKey), nil
}

func (a *Auth) GetSession(sessionId string) (*Session, error) {
	a.validateSessionIdArgument(sessionId)
	dbSession, dbUser, err := a.getDatabaseSessionAndUser(sessionId)
	if err != nil {
		return nil, err
	}
	user := a.TransformDatabaseUser(*dbUser)
	return a.TransformDatabaseSession(*dbSession, SessionContext{
		User:  *user,
		Fresh: false,
	}), nil
}

func (a *Auth) GetAllUserSessions(userId string) ([]Session, error) {
	var wg sync.WaitGroup
	var user *User
	var dbSessions []SessionSchema
	var err error

	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err = a.GetUser(userId)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		dbSessions, err = a.Adapter.GetSessionsByUserId(userId)
	}()

	wg.Wait()
	if err != nil {
		return nil, err
	}

	var validStoredUserSessions []Session
	for _, dbSession := range dbSessions {
		if IsValidDatabaseSession(&dbSession) {
			transformedSession := a.TransformDatabaseSession(dbSession, SessionContext{
				User:  *user,
				Fresh: false,
			})
			validStoredUserSessions = append(validStoredUserSessions, *transformedSession)
		}
	}

	return validStoredUserSessions, nil
}
