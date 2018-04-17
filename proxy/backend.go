package proxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/playdots/underpants/auth"
	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/user"

	"go.uber.org/zap"
)

// Backend is an http.Handler that handles traffic to that particular route.
type Backend struct {
	Ctx *config.Context

	Route *config.RouteInfo

	AuthProvider auth.Provider
}

// Copy the HTTP headers from one collection to another.
func copyHeaders(dst, src http.Header) {
	for key, vals := range src {
		for _, val := range vals {
			dst.Add(key, val)
		}
	}
}

func (b *Backend) serveHTTPAuth(w http.ResponseWriter, r *http.Request) {
	c, p := r.FormValue("c"), r.FormValue("p")
	if c == "" || !strings.HasPrefix(p, "/") {
		http.Error(w,
			http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}

	// verify the cookie
	if _, err := user.DecodeAndVerify(c, b.Ctx.Key); err != nil {
		// do not redirect out of here because this indicates a big
		// problem and we're likely to get into a redir loop.
		http.Error(w,
			http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	http.SetCookie(w, user.CreateCookie(c, b.Ctx.HasCerts()))

	// Redirect validates the redirect path.
	http.Redirect(w, r, p, http.StatusFound)
}

func (b *Backend) serveHTTPProxy(w http.ResponseWriter, r *http.Request) {
	u, err := user.DecodeFromRequest(r, b.Ctx.Key)
	if err != nil {
		zap.L().Info("authentication required",
			zap.String("host", r.Host),
			zap.String("uri", r.RequestURI))
		http.Redirect(w, r,
			b.AuthProvider.GetAuthURL(b.Ctx, r),
			http.StatusFound)
		return
	}

	if !b.Ctx.UserMemberOfAny(u.Email, b.Route.AllowedGroups) {
		zap.L().Info("access denied (not in group)",
			zap.String("from", b.Route.From),
			zap.String("user", u.Email))
		http.Error(w,
			"Forbidden: you are not a member of a group authorized to view this site.",
			http.StatusForbidden)
		return
	}

	rebase, err := b.Route.ToURL().Parse(
		strings.TrimLeft(r.URL.RequestURI(), "/"))
	if err != nil {
		panic(err)
	}

	br, err := http.NewRequest(r.Method, rebase.String(), r.Body)
	if err != nil {
		panic(err)
	}

	// Without passing on the original Content-Length, http.Client will use
	// Transfer-Encoding: chunked which some HTTP servers fall down on.
	br.ContentLength = r.ContentLength

	copyHeaders(br.Header, r.Header)

	// User information is passed to backends as headers.
	br.Header.Add("Underpants-Email", url.QueryEscape(u.Email))
	br.Header.Add("Underpants-Name", url.QueryEscape(u.Name))

	zap.L().Info("proxying request",
		zap.String("from", b.Route.From),
		zap.String("uri", r.RequestURI),
		zap.String("dest", rebase.String()),
		zap.String("user", u.Email))

	bp, err := http.DefaultTransport.RoundTrip(br)
	if err != nil {
		panic(err)
	}
	defer bp.Body.Close()

	copyHeaders(w.Header(), bp.Header)
	w.WriteHeader(bp.StatusCode)
	if _, err := io.Copy(w, bp.Body); err != nil {
		panic(err)
	}
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, auth.BaseURI) {
		b.serveHTTPAuth(w, r)
	} else {
		b.serveHTTPProxy(w, r)
	}
}
