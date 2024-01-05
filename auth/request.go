package auth

import (
	"net/url"
	"strings"

	"github.com/rohitp934/guam/utils"
)

type GuamRequest struct {
	Headers Headers
	URL     *string
	Method  string
}

type RequestContext struct {
	SessionCookie *string
	SetCookie     func(cookie Cookie)
	Request       GuamRequest
}

type Middleware func(context MiddlewareContext) MiddlewareRequestContext

type MiddlewareContext struct {
	SessionCookieName string
	Args              []any
	Env               Env
}

type MiddlewareRequestContext struct {
	SessionCookie *string
	SetCookie     func(cookie Cookie)
	Request       MiddlewareRequest
}

type MiddlewareRequest struct {
	Headers             Headers
	URL                 *string
	StoredSessionCookie *string
	Method              string
}

type Headers struct {
	Origin        *string
	Cookie        *string
	Authorization *string
	Host          *string
}

type CSRFProtection struct {
	Host              *string
	HostHeader        *string
	AllowedSubDomains []string
}

type AuthRequest struct {
	storedSessionId          *string
	bearerToken              *string
	cachedValidatePromise    *Session
	cachedBearerTokenPromise *Session
	requestContext           RequestContext
	auth                     Auth
}

type AuthRequestConfig struct {
	csrfProtection        *CSRFProtection
	reqContext            RequestContext
	csrfProtectionEnabled bool
}

func NewAuthRequest(auth Auth, config AuthRequestConfig) *AuthRequest {
	logger.Debug("New Auth Req:", config.reqContext.Request.Method)
	if config.reqContext.Request.URL != nil {
		logger.Debugln(" ", config.reqContext.Request.URL)
	} else {
		logger.Debugln(" ", "(url unknown)")
	}

	ar := &AuthRequest{
		requestContext: config.reqContext,
		auth:           auth,
	}

	var csrfProtectionConfig CSRFProtection
	var csrfProtectionEnabled bool
	if config.csrfProtection.Host != nil {
		csrfProtectionConfig = *config.csrfProtection
		csrfProtectionEnabled = true
	} else {
		csrfProtectionEnabled = config.csrfProtectionEnabled
	}

	if !csrfProtectionEnabled || ar.isValidRequestOrigin(csrfProtectionConfig) {
		var storedSessionId *string
		if ar.requestContext.SessionCookie != nil {
			storedSessionId = ar.requestContext.SessionCookie
		} else {
			storedSessionId = auth.ReadSessionCookie(ar.requestContext.Request.Headers.Cookie)
		}
		ar.storedSessionId = storedSessionId
	} else {
		ar.storedSessionId = nil
	}

	ar.bearerToken = auth.ReadBearerToken(ar.requestContext.Request.Headers.Authorization)

	return ar
}

func (ar *AuthRequest) SetSession(session *Session) {
	var sessionId *string
	if session != nil {
		sessionId = &session.SessionId
	} else {
		ar.cachedValidatePromise = nil
		sessionId = nil
	}

	if *ar.storedSessionId == *sessionId {
		return
	}

	ar.setSessionCookie(session)
}

func (ar *AuthRequest) setSessionCookie(session *Session) {
	var sessionId *string
	if session != nil {
		sessionId = &session.SessionId
	} else {
		sessionId = nil
	}

	if *ar.storedSessionId == *sessionId {
		return
	}

	ar.requestContext.SetCookie(ar.auth.CreateSessionCookie(session))
	if session != nil {
		logger.Debugln("Session cookie stored", session.SessionId)
	} else {
		logger.Debugln("Session cookie deleted")
	}
}

func (ar *AuthRequest) Validate() *Session {
	if ar.cachedValidatePromise != nil {
		return ar.cachedValidatePromise
	}
	if ar.storedSessionId == nil {
		return nil
	}

	session, err := ar.auth.ValidateSession(*ar.storedSessionId)
	if err != nil {
		ar.SetSession(nil)
		return nil
	}

	if session.Fresh {
		ar.SetSession(session)
	}
	ar.cachedValidatePromise = session
	return session
}

func (ar *AuthRequest) ValidateBearerToken() *Session {
	if ar.cachedBearerTokenPromise != nil {
		return ar.cachedBearerTokenPromise
	}
	if ar.bearerToken == nil {
		return nil
	}

	session, err := ar.auth.ValidateSession(*ar.bearerToken)
	if err != nil {
		return nil
	}

	return session
}

func (ar *AuthRequest) Invalidate() {
	ar.cachedBearerTokenPromise = nil
	ar.cachedValidatePromise = nil
}

func (ar *AuthRequest) isValidRequestOrigin(config CSRFProtection) bool {
	req := ar.requestContext.Request
	whitelist := []string{"GET", "HEAD", "OPTIONS", "TRACE"}

	for _, method := range whitelist {
		if method == strings.ToUpper(req.Method) {
			return true
		}
	}

	reqOrigin := req.Headers.Origin
	if reqOrigin == nil {
		logger.Errorln("No request origin available")
		return false
	}

	var host *string = nil
	if config.Host != nil {
		host = config.Host
	} else if req.URL != nil {
		parsedUrl, err := url.Parse(*req.URL)
		if err == nil {
			host = &parsedUrl.Host
		}
	}
	logger.Debug("Host ")
	if host != nil {
		logger.Debugln(*host)
	} else {
		logger.Debugln("(host unknown)")
	}

	if host != nil && utils.IsAllowedOrigin(*reqOrigin, *host, config.AllowedSubDomains) {
		logger.Debugln("Valid request origin", reqOrigin)
		return true
	}
	logger.Debugln("Invalid request origin", reqOrigin)
	return false
}

func TransformRequestContext(
	middlewareReqContext MiddlewareRequestContext,
) *RequestContext {
	return &RequestContext{
		Request: GuamRequest{
			URL:     middlewareReqContext.Request.URL,
			Method:  middlewareReqContext.Request.Method,
			Headers: middlewareReqContext.Request.Headers,
		},
		SetCookie:     middlewareReqContext.SetCookie,
		SessionCookie: middlewareReqContext.SessionCookie,
	}
}
