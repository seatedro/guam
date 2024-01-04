package utils

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type CookieAttributes struct {
	Domain   *string
	Encode   func(value string) string
	Expires  *time.Time
	MaxAge   *int
	Path     *string
	Priority *string
	SameSite *string
	HttpOnly bool
	Secure   bool
}

func ParseCookie(str string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(str, ";") {
		if equalIndex := strings.Index(part, "="); equalIndex >= 0 {
			key := strings.TrimSpace(part[:equalIndex])
			value := strings.TrimSpace(part[equalIndex+1:])

			// Decode the value, ignoring any decoding error.
			if decodedValue, err := url.QueryUnescape(value); err == nil {
				value = decodedValue
			}

			if _, exists := result[key]; !exists {
				result[key] = value
			}
		}
	}
	return result
}

func SerializeCookie(name, val string, options *CookieAttributes) (string, error) {
	if options == nil {
		options = &CookieAttributes{}
	}

	if options.Encode == nil {
		options.Encode = url.QueryEscape
	}

	value := options.Encode(val)
	str := name + "=" + value

	if options.MaxAge != nil && *options.MaxAge > 0 {
		str += "; Max-Age=" + strconv.Itoa(*options.MaxAge)
	}

	if options.Domain != nil {
		str += "; Domain=" + *options.Domain
	}

	if options.Path != nil {
		str += "; Path=" + *options.Path
	}

	if options.Expires != nil {
		str += "; Expires=" + options.Expires.Format(time.RFC1123)
	}

	if options.HttpOnly {
		str += "; HttpOnly"
	}

	if options.Secure {
		str += "; Secure"
	}

	if options.Priority != nil {
		switch strings.ToLower(*options.Priority) {
		case "low":
			str += "; Priority=Low"
		case "medium":
			str += "; Priority=Medium"
		case "high":
			str += "; Priority=High"
		default:
			return "", errors.New("invalid priority")
		}
	}

	if options.SameSite != nil {
		sameSite := strings.ToLower(*options.SameSite)
		switch sameSite {
		case "lax":
			str += "; SameSite=Lax"
		case "strict":
			str += "; SameSite=Strict"
		case "none":
			str += "; SameSite=None"
		default:
			return "", errors.New("invalid SameSite")
		}
	}
	return str, nil
}
