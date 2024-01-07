package auth

import (
	"time"

	"github.com/rohitp934/guam/utils"
)

const DEFAULT_SESSION_COOKIE_NAME = "auth_session"

type SessionCookieConfiguration struct {
	Name       string
	Attributes SessionCookieAttributes
	Expires    bool
}

type SessionCookieAttributes struct {
	SameSite string
	Path     string
	Domain   *string
}

type Cookie struct {
	Attributes *utils.CookieAttributes
	Name       string
	Value      string
}

func (c *Cookie) Serialize() (string, error) {
	return utils.SerializeCookie(c.Name, c.Value, c.Attributes)
}

type SessionOptions struct {
	cookie SessionCookieConfiguration
	env    Env
}

func NewSessionCookie(session *Session, options SessionOptions) *Cookie {
	var expires time.Time
	if session == nil {
		expires = time.Unix(0, 0)
	} else if options.cookie.Expires {
		expires = *session.IdlePeriodExpiresAt
	} else {
		expires = time.Now().Add(365 * 24 * time.Hour)
	}

	sameSite := options.cookie.Attributes.SameSite
	if sameSite == "" {
		sameSite = "lax"
	}

	path := options.cookie.Attributes.Path
	if path == "" {
		path = "/"
	}
	cookieName := options.cookie.Name
	if cookieName == "" {
		cookieName = DEFAULT_SESSION_COOKIE_NAME
	}

	sessionId := ""
	if session != nil {
		sessionId = session.SessionId
	}

	attributes := utils.CookieAttributes{
		Expires:  &expires,
		HttpOnly: true,
		Secure:   options.env == ENV_PRODUCTION,
		SameSite: &sameSite,
		Path:     &path,
		Domain:   options.cookie.Attributes.Domain,
		Encode:   nil,
		MaxAge:   nil,
		Priority: nil,
	}
	return NewCookie(cookieName, sessionId, attributes)
}

func NewCookie(name, value string, attributes utils.CookieAttributes) *Cookie {
	return &Cookie{
		Name:       name,
		Value:      value,
		Attributes: &attributes,
	}
}
