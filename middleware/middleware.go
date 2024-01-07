package middleware

import (
	"net/http"
	"strings"

	"github.com/rohitp934/guam/auth"
)

func createHeadersFromObject(headerObj map[string][]string) auth.Headers {
	h := make(map[string]string)
	for k, v := range headerObj {
		h[k] = strings.Join(v, ", ")
	}

	headers := auth.Headers{}

	origin, ok := h["Origin"]
	if ok {
		headers.Origin = &origin
	}

	cookie, ok := h["Cookie"]
	if ok {
		headers.Cookie = &cookie
	}

	authn, ok := h["Authorization"]
	if ok {
		headers.Authorization = &authn
	}

	host, ok := h["Host"]
	if ok {
		headers.Host = &host
	}

	return headers
}

func HttpMiddleware() auth.Middleware {
	return func(context auth.MiddlewareContext) auth.MiddlewareRequestContext {
		var w http.ResponseWriter
		var r *http.Request
		w = context.Args[0].(http.ResponseWriter)
		r = context.Args[1].(*http.Request)
		h := createHeadersFromObject(r.Header)
		return auth.MiddlewareRequestContext{
			Request: auth.MiddlewareRequest{
				Method:  r.Method,
				Headers: h,
			},
			SetCookie: func(cookie auth.Cookie) {
				c, err := cookie.Serialize()
				if err != nil {
					return
				}
				w.Header().Add("Set-Cookie", c)
			},
		}
	}
}
