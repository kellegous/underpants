package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/auth/google"
	"github.com/kellegous/underpants/auth/okta"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/mux"
	"github.com/kellegous/underpants/user"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	// the name of the auth cookie
	userCookieKey = "u"

	// maximum age (in seconds) of an authorization cookie before we'll force
	// revalidation
	authMaxAge = 3600
)

// decodeAndVerifyUser decodes the user from the cookie value and then verifies
// that it is valid.
func decodeAndVerifyUser(val string, key []byte) (*user.Info, error) {
	u, err := user.Decode(val, key)
	if err != nil {
		return nil, err
	}

	if time.Now().Sub(u.LastAuthenticated).Seconds() >= authMaxAge {
		return nil, fmt.Errorf("Cookie too old for: %s", u.Email)
	}

	return u, nil
}

// Represents a route to a backend. This is fully immutable after construction and will
// be shared among http serving go routines.
type disp struct {
	// A copy of the original configuration
	ctx *config.Context

	prv auth.Provider

	// The host of the hub consistent with url.URL.Host, which is essentially the entire
	// authority of the URL. Examples: hub.monetology.com or hub.monetology.com:4080
	host string

	// The route to the relevant backend
	route *url.URL

	// The signing key to use for authenticity
	// TODO(knorton): Move to context.
	key []byte

	// The groups which may access this backend.
	groups []string
}

// Copy the HTTP headers from one collection to another.
func copyHeaders(dst, src http.Header) {
	for key, vals := range src {
		for _, val := range vals {
			dst.Add(key, val)
		}
	}
}

// Extract a user object from the http request.  The key is used for HMAC
// signature verification.
func userFrom(r *http.Request, key []byte) (*user.Info, error) {
	c, err := r.Cookie(userCookieKey)
	if err != nil || c.Value == "" {
		return nil, errors.New("empty cookie")
	}

	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil, errors.New("unable to escape cookie")
	}

	u, err := decodeAndVerifyUser(v, key)
	if err != nil {
		return nil, errors.New("could not decode and verify user")
	}

	return u, nil
}

func userMemberOf(c *config.Info, u *user.Info, groups []string) bool {
	for _, group := range groups {
		if group == "*" {
			return true
		}

		for _, allowedUser := range c.Groups[group] {
			if u.Email == allowedUser {
				return true
			}
		}
	}

	return false
}

// getAuthProvider returns the auth.Provider that was configured in the config info.
func getAuthProvider(cfg *config.Info) (auth.Provider, error) {
	switch cfg.Oauth.Provider {
	case google.Name, "":
		return google.Provider, nil
	case okta.Name:
		return okta.Provider, nil
	}

	return nil, fmt.Errorf("invalid oauth provider: %s", cfg.Oauth.Provider)
}

// serveHTTPProxy serves the response by proxying it to the backend represented by the disp object.
func serveHTTPProxy(d *disp, w http.ResponseWriter, r *http.Request) {
	u, err := userFrom(r, d.key)
	if err != nil {
		zap.L().Info("authentication required",
			zap.String("host", r.Host),
			zap.String("uri", r.RequestURI))
		http.Redirect(w, r,
			d.prv.GetAuthURL(d.ctx, r),
			http.StatusFound)
		return
	}

	if d.ctx.HasGroups() {
		if !userMemberOf(d.ctx.Info, u, d.groups) {
			zap.L().Info("access denied (not in group)",
				zap.String("host", d.host),
				zap.String("user", u.Email))
			http.Error(w,
				"Forbidden: you are not a member of a group authorized to view this site.",
				http.StatusForbidden)
			return
		}
	}

	rebase, err := d.route.Parse(strings.TrimLeft(r.URL.RequestURI(), "/"))
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
		zap.String("host", d.host),
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

// Serve the request as an authentication request.
func serveHTTPAuth(d *disp, w http.ResponseWriter, r *http.Request) {
	c, p := r.FormValue("c"), r.FormValue("p")
	if c == "" || !strings.HasPrefix(p, "/") {
		http.Error(w,
			http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}

	// verify the cookie
	if _, err := decodeAndVerifyUser(c, d.key); err != nil {
		// do not redirect out of here because this indicates a big
		// problem and we're likely to get into a redir loop.
		http.Error(w,
			http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     userCookieKey,
		Value:    url.QueryEscape(c),
		Path:     "/",
		MaxAge:   authMaxAge,
		HttpOnly: true,
		Secure:   d.ctx.HasCerts(),
	})

	// TODO(knorton): validate the url string because it could totally
	// be used to fuck with the http message.
	http.Redirect(w, r, p, http.StatusFound)
}

// Serve the request for a particular route.
func (d *disp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, auth.BaseURI) {
		serveHTTPAuth(d, w, r)
	} else {
		serveHTTPProxy(d, w, r)
	}
}

// Generate a new random key for HMAC signing. Server keys are completely emphemeral
// in that the key is generated at server startup and not persisted between restarts.
// This means all cookies are invalidated just by restarting the server. This is
// generally desirable since it is "easy" for clients to re-authenticate with OAuth.
func newKey() ([]byte, error) {
	var b bytes.Buffer
	if _, err := io.CopyN(&b, rand.Reader, 64); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Construct a proper hostname (name:port) but taking into account standard ports
// where the port specification should be omitted.
func hostOf(name string, port int) string {
	switch port {
	case 80, 443:
		return name
	}
	return fmt.Sprintf("%s:%d", name, port)
}

func addSecurityHeaders(c *config.Info, next http.Handler) http.Handler {
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

func addSecurityHeadersFunc(
	c *config.Info,
	next func(http.ResponseWriter, *http.Request)) http.Handler {
	return addSecurityHeaders(c, http.HandlerFunc(next))
}

// Setup all handlers in a ServeMux.
func setup(ctx *config.Context) (*mux.Serve, error) {
	mb := mux.Create()

	// Construct the HMAC signing key
	key, err := newKey()
	if err != nil {
		return nil, err
	}

	p, err := getAuthProvider(ctx.Info)
	if err != nil {
		return nil, err
	}

	// setup routes
	for _, r := range ctx.Routes {
		host := hostOf(r.From, ctx.Port)
		route, err := url.Parse(r.To)
		if err != nil {
			return nil, err
		}

		mb.ForHost(host).Handle("/",
			addSecurityHeaders(ctx.Info, &disp{
				ctx:    ctx,
				prv:    p,
				route:  route,
				host:   host,
				key:    key,
				groups: r.AllowedGroups,
			}))
	}

	// load the template for the one piece of static content embedded in
	// the server
	t := template.Must(template.New("index.html").Parse(rootTmpl))

	// setup admin
	mb.ForAnyHost().Handle("/",
		addSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					u, _ := userFrom(r, key)
					w.Header().Set("Content-Type", "text/html;charset=utf-8")
					if debugTmpl {
						t, err := template.ParseFiles("index.html")
						if err != nil {
							panic(err)
						}
						t.Execute(w, u)
						return
					}
					t.Execute(w, u)
				default:
					http.NotFound(w, r)
				}
			}))

	mb.ForAnyHost().Handle(auth.BaseURI,
		addSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				u, back, err := p.Authenticate(ctx, r)
				if err != nil {
					http.Error(w,
						http.StatusText(http.StatusForbidden),
						http.StatusForbidden)
					return
				}

				u.LastAuthenticated = time.Now()

				v, err := u.Encode(key)
				if err != nil {
					panic(err)
				}

				http.SetCookie(w, &http.Cookie{
					Name:     userCookieKey,
					Value:    url.QueryEscape(v),
					Path:     "/",
					MaxAge:   authMaxAge,
					HttpOnly: true,
					Secure:   ctx.HasCerts(),
				})

				p := back.Path
				if back.RawQuery != "" {
					p += fmt.Sprintf("?%s", back.RawQuery)
				}

				http.Redirect(w, r,
					fmt.Sprintf("%s://%s%s?%s", ctx.Scheme(), back.Host, auth.BaseURI,
						url.Values{
							"p": {p},
							"c": {v},
						}.Encode()),
					http.StatusFound)
			}))

	mb.ForAnyHost().Handle(fmt.Sprintf("%slogout", auth.BaseURI),
		addSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w,
						http.StatusText(http.StatusMethodNotAllowed),
						http.StatusMethodNotAllowed)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:   userCookieKey,
					Value:  "",
					Path:   "/",
					MaxAge: 0,
				})

				// TODO(knorton): Convert this to simple html page
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintln(w, "ok.")
			}))

	return mb.Build(), nil
}

// LoadCertificate loads the TLS certificate from the speciified files. The key file can be an encryped
// PEM so long as it carries the appropriate headers (Proc-Type and Dek-Info) and the
// password will be requested interactively.
func LoadCertificate(crtFile, keyFile string) (tls.Certificate, error) {
	crtBytes, err := ioutil.ReadFile(crtFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDer, _ := pem.Decode(keyBytes)
	if keyDer == nil {
		return tls.Certificate{}, fmt.Errorf("%s cannot be decoded", keyFile)
	}

	// http://www.ietf.org/rfc/rfc1421.txt
	if !strings.HasPrefix(keyDer.Headers["Proc-Type"], "4,ENCRYPTED") {
		return tls.X509KeyPair(crtBytes, keyBytes)
	}

	fmt.Printf("%s\nPassword: ", keyFile)
	pwd, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDec, err := x509.DecryptPEMBlock(keyDer, pwd)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(crtBytes, pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   keyDec,
	}))
}

// ListenAndServe binds the listening port and start serving traffic.
func ListenAndServe(ctx *config.Context, m http.Handler) error {
	if ctx.HasCerts() {
		var certs []tls.Certificate
		for _, item := range ctx.Certs {
			crt, err := LoadCertificate(item.Crt, item.Key)
			if err != nil {
				return err
			}

			certs = append(certs, crt)
		}

		addr := ctx.ListenAddr()

		s := &http.Server{
			Addr:    addr,
			Handler: m,
			TLSConfig: &tls.Config{
				NextProtos:   []string{"http/1.1"},
				Certificates: certs,
				MinVersion:   tls.VersionTLS10,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				},
				PreferServerCipherSuites: true,
			},
		}

		s.TLSConfig.BuildNameToCertificate()

		conn, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		return s.Serve(tls.NewListener(conn, s.TLSConfig))
	}

	return http.ListenAndServe(ctx.ListenAddr(), m)
}

func contextFrom(cfg *config.Info, port int) *config.Context {
	if port == 0 {
		if cfg.HasCerts() {
			port = 443
		} else {
			port = 80
		}
	}

	return &config.Context{
		Info: cfg,
		Port: port,
	}
}

func setupLogger() error {
	lg, err := zap.NewProduction()
	if err != nil {
		return err
	}

	zap.ReplaceGlobals(lg)
	return nil
}

func main() {
	flagPort := flag.Int("port", 0, "")
	flagConf := flag.String("conf", "underpants.json", "")

	flag.Parse()

	if err := setupLogger(); err != nil {
		log.Panic(err)
	}

	zap.L().Info("starting",
		zap.Int("port", *flagPort),
		zap.String("conf", *flagConf))

	var cfg config.Info
	if err := cfg.ReadFile(*flagConf); err != nil {
		panic(err)
	}

	ctx := contextFrom(&cfg, *flagPort)

	m, err := setup(ctx)
	if err != nil {
		panic(err)
	}

	if err := ListenAndServe(ctx, m); err != nil {
		panic(err)
	}
}

const debugTmpl = false
const rootTmpl = `
<html>
  <head>
    <title></title>
    <style>
    body {
      font-family: HelveticaNeue-Light,Arial,sans-serif;
      font-size: 24pt;
      color: #666;
      background-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAPCAIAAAHt9hMZAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYxIDY0LjE0MDk0OSwgMjAxMC8xMi8wNy0xMDo1NzowMSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNS4xIFdpbmRvd3MiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6N0RBOEYzNTNEQkE5MTFFMTgwMkJFNjk4ODI1NkM0ODEiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6N0RBOEYzNTREQkE5MTFFMTgwMkJFNjk4ODI1NkM0ODEiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo3REE4RjM1MURCQTkxMUUxODAyQkU2OTg4MjU2QzQ4MSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo3REE4RjM1MkRCQTkxMUUxODAyQkU2OTg4MjU2QzQ4MSIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Ph88gYkAAAB1SURBVHjaYnjz5s1/MAAyGIEUAwwABBADRAxIIoQBAghVAQwwvX37FsJCZgAEEEI/MgOHCQzYABO6iWAAEEDYTcBuAHaHYWOQYioD0QAggLCHAbGhQr7VTMR4mQRfD5S9AAFGQqxQP0lQ2S8kuJGB2mBk+hoAwlXWrXM6SBoAAAAASUVORK5C");
    }
    #user {
      width: 350px;
      height: 400px;
      margin: 100px auto;
      border: 1px solid #eee;
      box-shadow: 2px 2px 15px rgba(0, 0, 0, 0.1);
      background-color: #fff;
      background-image: -webkit-linear-gradient(left, #fafafa, #fff 15%, #fff 85%, #fafafa);
      position: relative;
      text-align: center;
    }
    #pict {
      width: 200px;
      height: 200px;
      margin: 10px auto;
      background-size: cover;
      border-radius: 500px;
      box-shadow: inset 10px -10px 20px rgba(0, 0, 0, 0.2);
      border: 2px solid #ccc;
      background-color: #666;
    }
    #name {
      text-align: center;
      text-shadow: 2px 2px 4px #ddd;
    }
    #ctrl {
      position: absolute;
      bottom: 10px;
      left: 0;
      right: 0;
      text-align: center;
      margin: 0;
    }
    #ctrl button {
      position: relative;
      border: none;
      width: 40px;
      height: 40px;
      background-color: transparent;
      background-size: 40px 40px;
      opacity: 0.8;
      background-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA2hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDowMTgwMTE3NDA3MjA2ODExODIyQTlDMzJGRDM2NjlFOCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo0RTQ0RDBGMkU2MEQxMUUxOThFMkZBOTQ0NTJDOUI5MSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo0RTQ0RDBGMUU2MEQxMUUxOThFMkZBOTQ0NTJDOUI5MSIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M2IChNYWNpbnRvc2gpIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QTIyQjg0MEY0RDIxNjgxMTgyMkE5QzMyRkQzNjY5RTgiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6MDE4MDExNzQwNzIwNjgxMTgyMkE5QzMyRkQzNjY5RTgiLz4gPC9yZGY6RGVzY3Jp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");
    }
    #ctrl button:hover {
      opacity: 1;
    }
    #ctrl .l {
      pointer-events: none;
      opacity: 0;
      position: absolute;
      font-size: 16px;
      top: 46px;
      left: -24px;
      background-color: #333;
      color: #fff;
      padding: 10px;
      border-radius: 4px;
      width: 70px;
      box-shadow: -2px 2px 10px rgba(0, 0, 0, 0.2);
      -webkit-transition: opacity .2s ease-in-out;
    }
    #ctrl button:hover .l {
      opacity: 1.0;
    }
    #ctrl .l div {
      position: absolute;
      top: -6px;
      left: 38px;
      -webkit-transform: rotate(45deg);
      width: 12px;
      height: 12px;
      background-color: #333;
    }
    </style>
  </head>
  <body>
    <div id="user">
      {{with .}}
      <div id="pict" style="background-image: url('{{.Picture}}')"></div>
      <div id="name">{{.Name}}</div>
      <form id="ctrl" method="POST" action="/__auth__/logout">
        <input name="x" type="hidden">
        <button type="submit">
          <div class="l"><div></div>logout</div>
        </button>
      </form>
      {{else}}
      <div id="pict"></div>
      <div id="name">Nobody Doe</div>
      {{end}}
    </div>
  </body>
</html>
`
