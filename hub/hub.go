package hub

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/internal"
	"github.com/kellegous/underpants/mux"
	"github.com/kellegous/underpants/user"
)

// Setup ...
func Setup(ctx *config.Context, prv auth.Provider, mb *mux.Builder) {
	// load the template for the one piece of static content embedded in
	// the server
	t := template.Must(template.New("index.html").Parse(rootTmpl))

	// setup admin
	mb.ForAnyHost().Handle("/",
		internal.AddSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					u, _ := user.DecodeFromRequest(r, ctx.Key)
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
		internal.AddSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				u, back, err := prv.Authenticate(ctx, r)
				if err != nil {
					http.Error(w,
						http.StatusText(http.StatusForbidden),
						http.StatusForbidden)
					return
				}

				u.LastAuthenticated = time.Now()

				v, err := u.Encode(ctx.Key)
				if err != nil {
					panic(err)
				}

				http.SetCookie(w, user.CreateCookie(v, ctx.HasCerts()))

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
		internal.AddSecurityHeadersFunc(ctx.Info,
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w,
						http.StatusText(http.StatusMethodNotAllowed),
						http.StatusMethodNotAllowed)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:   user.CookieKey,
					Value:  "",
					Path:   "/",
					MaxAge: 0,
				})

				// TODO(knorton): Convert this to simple html page
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintln(w, "ok.")
			}))
}
