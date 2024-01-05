package utils

import (
	"net/url"
	"strings"
)

func GetBaseDomain(host string) string {
	if strings.HasPrefix(host, "localhost:") {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func IsAllowedOrigin(origin, host string, allowedSubdomains []string) bool {
	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := parsedOrigin.Host

	baseDomain := GetBaseDomain(host)
	if len(host) < 1 || len(origin) < 1 {
		return false
	}
	if originHost == host {
		return true
	}
	if len(allowedSubdomains) == 1 && allowedSubdomains[0] == "*" {
		return strings.HasSuffix(originHost, "."+baseDomain)
	}
	for _, subdomain := range allowedSubdomains {
		allowedHost := baseDomain
		if subdomain != "" {
			allowedHost = subdomain + "." + baseDomain
		}
		if allowedHost == originHost {
			return true
		}
	}
	return false
}
