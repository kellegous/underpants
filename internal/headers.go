package internal

import (
	"net/http"

	"github.com/kellegous/underpants/config"
)

// AddSecurityHeaders ...
func AddSecurityHeaders(c *config.Info, next http.Handler) http.Handler {
	if c.AddSecurityHeaders {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.HasCerts() {
				w.Header().Add("Strict-Transport-Security", "max-age=16070400; includeSubDomains")
			}

			w.Header().Add("X-Frame-Options", "SAMEORIGIN")
			w.Header().Add("Cache-Control", "private, no-cache")
			w.Header().Add("Pragma", "no-cache")
			next.ServeHTTP(w, r)
		})
	}
	return next
}

// AddSecurityHeadersFunc ...
func AddSecurityHeadersFunc(
	c *config.Info,
	next func(http.ResponseWriter, *http.Request)) http.Handler {
	return AddSecurityHeaders(c, http.HandlerFunc(next))
}
