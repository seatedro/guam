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

type FiberContext interface {
	Set(key string, value string)
	Method(override ...string) string
	GetReqHeaders() map[string][]string
}

func Fiber() auth.Middleware {
	return func(context auth.MiddlewareContext) auth.MiddlewareRequestContext {
		c := context.Args[0].(FiberContext)
		h := createHeadersFromObject(c.GetReqHeaders())
		return auth.MiddlewareRequestContext{
			Request: auth.MiddlewareRequest{
				Method:  c.Method(),
				Headers: h,
			},
			SetCookie: func(cookie auth.Cookie) {
				serializedCookie, err := cookie.Serialize()
				if err != nil {
					return
				}
				c.Set("Set-Cookie", serializedCookie)
			},
		}
	}
}

func Chi() auth.Middleware {
	return HttpMiddleware()
}

func GorillaMux() auth.Middleware {
	return HttpMiddleware()
}

type GinContext interface {
	Header(key, value string)
}

func Gin() auth.Middleware {
	return func(context auth.MiddlewareContext) auth.MiddlewareRequestContext {
		r := context.Args[0].(*http.Request)
		c := context.Args[1].(GinContext)
		h := createHeadersFromObject(r.Header)
		return auth.MiddlewareRequestContext{
			Request: auth.MiddlewareRequest{
				Method:  r.Method,
				Headers: h,
			},
			SetCookie: func(cookie auth.Cookie) {
				serializedCookie, err := cookie.Serialize()
				if err != nil {
					return
				}
				c.Header("Set-Cookie", serializedCookie)
			},
		}
	}
}
