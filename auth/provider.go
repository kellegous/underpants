package auth

import (
	"net/http"
	"net/url"

	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/user"
)

const (
	// BaseURI is the base path used for auth-related actions and callbacks. this will be
	// available on the hub as well as each of the routes.
	BaseURI = "/__auth__/"
)

// Provider ...
type Provider interface {
	GetAuthURL(ctx *config.Context, r *http.Request) string
	Authenticate(ctx *config.Context, r *http.Request) (*user.Info, *url.URL, error)
}

// GetCurrentURL returns the URL for the current request.
func GetCurrentURL(ctx *config.Context, r *http.Request) *url.URL {
	u := *r.URL
	u.Host = r.Host
	u.Scheme = ctx.Scheme()
	return &u
}
