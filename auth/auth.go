package auth

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rohitp934/guam/utils"

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
	ActivePeriodExpiresAt *time.Time
	IdlePeriodExpiresAt   *time.Time
	SessionAttributes     map[string]interface{}
	SessionId             string
	State                 SessionState
	Fresh                 bool
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
	UserAttributes map[string]interface{}
	UserId         string
}

type (
	GetUserAttributesFunc    func(databaseUser UserSchema) map[string]interface{}
	GetSessionAttributesFunc func(databaseSession SessionSchema) map[string]interface{}
	Configuration            struct {
		Adapter              Adapter
		PasswordHash         PasswordHash
		Middleware           Middleware
		SessionExpiresIn     *SessionExpires
		GetSessionAttributes GetSessionAttributesFunc
		GetUserAttributes    GetUserAttributesFunc
		SessionCookie        SessionCookieConfiguration
		CSRFProtection       CSRFProtection
		Env                  Env
		Experimental         Experimental
	}
)

type Middleware func(context MiddlewareContext) MiddlewareRequestContext

type MiddlewareContext struct {
	SessionCookieName string
	Args              []interface{}
	Env               Env
}

type MiddlewareRequestContext struct {
	SetCookie     func(cookie Cookie)
	Request       MiddlewareRequest
	SessionCookie string
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
	PasswordHash         *PasswordHash
	Middleware           Middleware
	GetUserAttributes    GetUserAttributesFunc
	GetSessionAttributes GetSessionAttributesFunc
	SessionCookieConfig  SessionCookieConfiguration
	CsrfProtection       CSRFProtection
	SessionExpiresIn     SessionExpires
	Env                  Env
	Experimental         Experimental
}

type SessionExpires struct {
	ActivePeriod int64
	IdlePeriod   int64
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
		ActivePeriod: int64(activePeriod),
		IdlePeriod:   int64(idlePeriod),
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

func (a *Auth) TransformDatabaseSession(
	databaseSession SessionSchema,
	context SessionContext,
) *Session {
	attributes := a.GetSessionAttributes(databaseSession)
	active := utils.IsWithinExpiration(databaseSession.ActiveExpires)

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

func (a *Auth) getDatabaseUser(userId string) (*UserSchema, error) {
	user, err := a.Adapter.GetUser(userId)
	if err != nil {
		logger.Errorln("User not found: ", userId)
		return nil, errors.New("AUTH_INVALID_USER_ID")
	}
	return user, nil
}

func (a *Auth) getDatabaseSession(sessionId string) (*SessionSchema, error) {
	session, err := a.Adapter.GetSession(sessionId)
	if err != nil {
		logger.Errorln("Session not found: ", sessionId)
		return nil, errors.New("AUTH_INVALID_SESSION_ID")
	}

	if !IsValidDatabaseSession(session) {
		logger.Errorf(
			"Session expired at %s",
			time.Unix(0, session.IdleExpires*int64(time.Millisecond)),
		)
		return nil, errors.New("AUTH_INVALID_SESSION_ID")
	}
	return session, nil
}

func (a *Auth) getDatabaseSessionAndUser(
	sessionId string,
) (*SessionSchema, *UserJoinSessionSchema, error) {
	if ad, ok := a.Adapter.(AdapterWithGetter); ok {
		session, user, err := ad.GetSessionAndUser(sessionId)
		if err != nil {
			logger.Errorln("Session not found: ", sessionId)
			return nil, nil, errors.New("AUTH_INVALID_SESSION_ID")
		}

		if !IsValidDatabaseSession(session) {
			logger.Errorf(
				"Session expired at %s",
				time.Unix(0, session.IdleExpires*int64(time.Millisecond)),
			)
			return nil, nil, errors.New("AUTH_INVALID_SESSION_ID")
		}

		return session, user, nil
	}
	session, err := a.getDatabaseSession(sessionId)
	if err != nil {
		logger.Errorln("Session not found: ", sessionId)
		return nil, nil, err
	}
	user, err := a.getDatabaseUser(session.UserID)
	if err != nil {
		logger.Errorln("User not found: ", session.UserID)
		return nil, nil, err
	}

	result := &UserJoinSessionSchema{
		UserSchema: *user,
		SessionID:  sessionId,
	}

	return session, result, nil
}

func (a *Auth) validateSessionIdArgument(sessionId string) error {
	if sessionId == "" {
		return errors.New("AUTH_INVALID_SESSION_ID")
	}

	return nil
}

func (a *Auth) getNewSessionExpiration(sessionExpiresIn *SessionExpires) (time.Time, time.Time) {
	var activePeriod, idlePeriod int64

	if sessionExpiresIn != nil {
		activePeriod = sessionExpiresIn.ActivePeriod
		idlePeriod = sessionExpiresIn.IdlePeriod
	} else {
		activePeriod = a.SessionExpiresIn.ActivePeriod
		idlePeriod = a.SessionExpiresIn.IdlePeriod
	}
	activeExpires := time.Now().
		Add(time.Duration(activePeriod) * time.Millisecond)
		// UnixNano() /
		// int64(
		// 	time.Millisecond,
		// )
	idleExpires := time.Now().
		Add(time.Duration(idlePeriod) * time.Millisecond)
		// UnixNano() /
		// int64(
		// 	time.Millisecond,
		// )
	return activeExpires, idleExpires
}

func (a *Auth) GetUser(userId string) (*User, error) {
	userSchema, err := a.getDatabaseUser(userId)
	if err != nil {
		logger.Errorln("User not found: ", userId)
		return nil, err
	}
	user := a.TransformDatabaseUser(*userSchema)
	return user, nil
}

type CreateUserKey struct {
	password       *string
	providerId     string
	providerUserId string
}
type CreateUserOptions struct {
	userId     *string
	key        *CreateUserKey
	attributes map[string]any
}

func (a *Auth) CreateUser(options CreateUserOptions) *User {
	var userId string
	if options.userId != nil {
		userId = *options.userId
	} else {
		userId = utils.GenerateRandomString(15, "")
	}

	var userAttributes map[string]any
	if options.attributes != nil {
		userAttributes = options.attributes
	} else {
		userAttributes = map[string]any{}
	}

	databaseUser := UserSchema{
		ID:         userId,
		Attributes: userAttributes,
	}

	if options.key == nil {
		err := a.Adapter.SetUser(databaseUser, nil)
		if err != nil {
			logger.Errorln("Error creating user")
			return nil
		}
		return a.TransformDatabaseUser(databaseUser)
	}

	keyId, err := CreateKeyId(options.key.providerId, options.key.providerUserId)
	if err != nil {
		logger.Errorln("Error creating key id")
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

func (a *Auth) UpdateUserAttributes(
	userId string,
	attributes map[string]any,
) (*User, error) {
	a.Adapter.UpdateUser(userId, attributes)
	return a.GetUser(userId)
}

func (a *Auth) DeleteUser(userId string) error {
	err := a.Adapter.DeleteSessionsByUserId(userId)
	if err != nil {
		logger.Errorln("Error deleting user sessions")
		return err
	}
	err = a.Adapter.DeleteKeysByUserId(userId)
	if err != nil {
		logger.Errorln("Error deleting user keys")
		return err
	}
	err = a.Adapter.DeleteUser(userId)
	if err != nil {
		logger.Errorln("Error deleting user")
		return err
	}

	return nil
}

func (a *Auth) UseKey(providerId, providerUserId string, password *string) (*Key, error) {
	keyId, err := CreateKeyId(providerId, providerUserId)
	if err != nil {
		logger.Errorln("Error creating key id")
		return nil, err
	}
	databaseKey, err := a.Adapter.GetKey(keyId)
	if err != nil {
		logger.Errorln("Key not found: ", keyId)
		return nil, errors.New("AUTH_INVALID_KEY_ID")
	}

	hashedPassword := databaseKey.HashedPassword
	if hashedPassword != nil {
		logger.Info("Key includes password")
		if password == nil {
			logger.Errorln("Key password not provided", keyId)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}

		validPassword := a.PasswordHash.validate(*password, *hashedPassword)
		if !validPassword {
			logger.Errorln("Incorrect key password", *password)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}
		logger.Infoln("Validated key password")
	} else {
		if password != nil {
			logger.Errorln("Incorrect key password", *password)
			return nil, errors.New("AUTH_INVALID_PASSWORD")
		}
		logger.Infoln("No password included in key")
	}
	logger.Infoln("Validated key", keyId)
	return a.TransformDatabaseKey(*databaseKey), nil
}

func (a *Auth) GetSession(sessionId string) (*Session, error) {
	err := a.validateSessionIdArgument(sessionId)
	if err != nil {
		logger.Errorln("Invalid session id: ", sessionId)
		return nil, err
	}

	dbSession, dbUser, err := a.getDatabaseSessionAndUser(sessionId)
	if err != nil {
		logger.Errorln("Error getting database session and user: ", sessionId)
		return nil, err
	}

	user := a.TransformDatabaseUser(dbUser.UserSchema)
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
		logger.Errorln("Error getting user sessions: ", userId)
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

func (a *Auth) ValidateSession(sessionId string) (*Session, error) {
	err := a.validateSessionIdArgument(sessionId)
	if err != nil {
		logger.Errorln("Invalid session id: ", sessionId)
		return nil, err
	}

	dbSession, dbUser, err := a.getDatabaseSessionAndUser(sessionId)
	if err != nil {
		logger.Errorln("Error getting database session and user: ", sessionId)
		return nil, err
	}

	user := a.TransformDatabaseUser(dbUser.UserSchema)
	session := a.TransformDatabaseSession(*dbSession, SessionContext{
		User:  *user,
		Fresh: false,
	})

	if session.State == StateActive {
		logger.Infoln("Validated session: ", sessionId)
		return session, nil
	}

	activePeriodExpiresAt, idlePeriodExpiresAt := a.getNewSessionExpiration(nil)
	err = a.Adapter.UpdateSession(sessionId, map[string]any{
		"active_expires": activePeriodExpiresAt.UnixNano() / int64(time.Millisecond),
		"idle_expires":   idlePeriodExpiresAt.UnixNano() / int64(time.Millisecond),
	})
	if err != nil {
		logger.Errorln("Error updating session: ", sessionId)
		return nil, err
	}

	logger.Infoln("Renewed session: ", sessionId)
	renewedSession := &Session{
		User:                  session.User,
		SessionId:             session.SessionId,
		SessionAttributes:     session.SessionAttributes,
		ActivePeriodExpiresAt: &activePeriodExpiresAt,
		IdlePeriodExpiresAt:   &idlePeriodExpiresAt,
		State:                 session.State,
		Fresh:                 true,
	}
	return renewedSession, nil
}

type CreateSessionOptions struct {
	sessionId  string
	userId     string
	attributes map[string]any
}

func (a *Auth) CreateSession(options CreateSessionOptions) (*Session, error) {
	activePeriodExpiresAt, idlePeriodExpiresAt := a.getNewSessionExpiration(nil)
	userId := options.userId
	var sessionId string
	if options.sessionId != "" {
		sessionId = options.sessionId
	} else {
		sessionId = utils.GenerateRandomString(40, "")
	}
	attributes := options.attributes
	dbSession := SessionSchema{
		ID:            sessionId,
		UserID:        userId,
		ActiveExpires: activePeriodExpiresAt.UnixMilli(),
		IdleExpires:   idlePeriodExpiresAt.UnixMilli(),
		Attributes:    attributes,
	}

	err := a.Adapter.SetSession(dbSession)
	if err != nil {
		logger.Errorln("Error creating session: ", sessionId)
		return nil, err
	}

	user, err := a.GetUser(userId)
	if err != nil {
		logger.Errorln("Error getting user: ", userId)
		return nil, err
	}

	return a.TransformDatabaseSession(dbSession, SessionContext{
		User:  *user,
		Fresh: false,
	}), nil
}

func (a *Auth) UpdateSessionAttributes(
	sessionId string,
	attributes map[string]any,
) (*Session, error) {
	err := a.validateSessionIdArgument(sessionId)
	if err != nil {
		logger.Errorln("Invalid session id: ", sessionId)
		return nil, err
	}
	err = a.Adapter.UpdateSession(sessionId, attributes)
	if err != nil {
		logger.Errorln("Error updating session: ", sessionId)
		return nil, err
	}
	return a.GetSession(sessionId)
}
