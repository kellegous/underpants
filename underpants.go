package main

import (
  "bytes"
  "code.google.com/p/goauth2/oauth"
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/json"
  "errors"
  "flag"
  "fmt"
  "io"
  "log"
  "net/http"
  "net/url"
  "os"
  "strings"
  "sync"
)

// TODO(knorton): allow websockets to pass.
// TODO(knorton): add minimal ui to hub just to see who you are and
//                perhaps who is passing.
const (
  userCookieKey  = "u"
  authPathPrefix = "/__auth__/"
)

type conf struct {
  Host  string
  Oauth struct {
    ClientId     string `json:"client-id"`
    ClientSecret string `json:"client-secret"`
    Scope        string `json:"scope"`
    Domain       string `json:"domain"`
  }
  Routes []struct {
    From string
    To   string
  }
}

type user struct {
  Email   string
  Name    string
  Picture string
}

// a really simple user cache to avoid having to fully decode
// hmac signatures.
// TODO(knorton): this cache grows unbounded
type Cache struct {
  l sync.RWMutex
  v map[string]*user
}

func (c *Cache) read(key string) (*user, bool) {
  log.Printf("read(%s)\n", key)
  c.l.RLock()
  defer c.l.RUnlock()
  u, ok := c.v[key]
  return u, ok
}

func (c *Cache) write(key string, u *user) {
  log.Printf("write(%s, %s)\n", key, u.Email)
  c.l.Lock()
  defer c.l.Unlock()
  c.v[key] = u
}

func (u *user) encode(key []byte) (string, error) {
  var b bytes.Buffer
  h := hmac.New(sha256.New, key)
  w := base64.NewEncoder(base64.URLEncoding,
    io.MultiWriter(h, &b))
  if err := json.NewEncoder(w).Encode(u); err != nil {
    return "", err
  }

  return fmt.Sprintf("%s,%s",
    base64.URLEncoding.EncodeToString(h.Sum(nil)),
    b.String()), nil
}

func validMessage(key []byte, sig, msg string) bool {
  s, err := base64.URLEncoding.DecodeString(sig)
  if err != nil {
    return false
  }

  h := hmac.New(sha256.New, key)
  h.Write([]byte(msg))
  v := h.Sum(nil)
  if len(v) != len(s) {
    return false
  }

  for i := 0; i < len(s); i++ {
    if s[i] != v[i] {
      return false
    }
  }

  return true
}

func decodeUser(c string, key []byte) (*user, error) {
  s := strings.SplitN(c, ",", 2)

  if len(s) != 2 || !validMessage(key, s[0], s[1]) {
    return nil, errors.New(fmt.Sprintf("Invalid user cookie: %s", c))
  }

  var u user
  r := base64.NewDecoder(base64.URLEncoding, bytes.NewBufferString(s[1]))
  if err := json.NewDecoder(r).Decode(&u); err != nil {
    return nil, err
  }

  return &u, nil
}

type disp struct {
  from   string
  to     string
  host   string
  key    []byte
  domain string
  oauth  *oauth.Config
  cache  *Cache
}

func (d *disp) AuthCodeUrl(u *url.URL) string {
  return fmt.Sprintf("%s&%s",
    d.oauth.AuthCodeURL(u.String()),
    url.Values{"hd": {d.domain}}.Encode())
}

func copyHeaders(dst, src http.Header) {
  for key, vals := range src {
    for _, val := range vals {
      dst.Add(key, val)
    }
  }
}

func userFrom(r *http.Request, cache *Cache, key []byte) *user {
  c, err := r.Cookie(userCookieKey)
  if err != nil || c.Value == "" {
    return nil
  }

  // check the cache
  if u, found := cache.read(c.Value); found {
    return u
  }

  v, err := url.QueryUnescape(c.Value)
  if err != nil {
    return nil
  }

  u, err := decodeUser(v, key)
  if err != nil {
    // TODO(knorton): log this.
    return nil
  }

  // this was a cache miss
  cache.write(c.Value, u)

  return u
}

func urlFor(host string, r *http.Request) *url.URL {
  u := *r.URL
  u.Host = host
  // TODO(knorton): Assume http for now.
  u.Scheme = "http"
  return &u
}

func serveHttpProxy(d *disp, w http.ResponseWriter, r *http.Request) {
  u := userFrom(r, d.cache, d.key)
  if u == nil {
    http.Redirect(w, r,
      d.AuthCodeUrl(urlFor(d.from, r)),
      http.StatusFound)
    return
  }

  br, err := http.NewRequest(r.Method, urlFor(d.to, r).String(), r.Body)
  if err != nil {
    panic(err)
  }

  copyHeaders(br.Header, r.Header)

  // TODO(knorton): Add special headers.
  c := http.Client{}
  bp, err := c.Do(br)
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

func serveHttpAuth(d *disp, w http.ResponseWriter, r *http.Request) {
  c, p := r.FormValue("c"), r.FormValue("p")
  if c == "" || !strings.HasPrefix(p, "/") {
    http.Error(w,
      http.StatusText(http.StatusBadRequest),
      http.StatusBadRequest)
    return
  }

  if _, found := d.cache.read(c); !found {
    if _, err := decodeUser(c, d.key); err != nil {
      // do not redirect out of here because this indicates a big
      // problem and we're likely to get into a redir loop.
      http.Error(w,
        http.StatusText(http.StatusForbidden),
        http.StatusForbidden)
      return
    }
  }

  http.SetCookie(w, &http.Cookie{
    Name:   userCookieKey,
    Value:  url.QueryEscape(c),
    Path:   "/",
    MaxAge: 3600,
  })

  // TODO(knorton): validate the url string because it could totally
  // be used to fuck with the http message.
  http.Redirect(w, r, p, http.StatusFound)
}

func (d *disp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  p := r.URL.Path
  if strings.HasPrefix(p, authPathPrefix) {
    serveHttpAuth(d, w, r)
  } else {
    serveHttpProxy(d, w, r)
  }
}

func oauthConfig(c *conf, port int) *oauth.Config {
  return &oauth.Config{
    ClientId:     c.Oauth.ClientId,
    ClientSecret: c.Oauth.ClientSecret,
    AuthURL:      "https://accounts.google.com/o/oauth2/auth",
    TokenURL:     "https://accounts.google.com/o/oauth2/token",
    Scope:        c.Oauth.Scope,
    RedirectURL:  fmt.Sprintf("http://%s%s", hostOf(c.Host, port), authPathPrefix),
  }
}

func config(filename string) (*conf, error) {
  f, err := os.Open(filename)
  if err != nil {
    return nil, err
  }
  defer f.Close()

  var c conf
  if err := json.NewDecoder(f).Decode(&c); err != nil {
    return nil, err
  }

  return &c, nil
}

func newKey() ([]byte, error) {
  var b bytes.Buffer
  if _, err := io.CopyN(&b, rand.Reader, 64); err != nil {
    return nil, err
  }

  return b.Bytes(), nil
}

func hostOf(name string, port int) string {
  switch port {
  case 80, 443:
    return name
  }
  return fmt.Sprintf("%s:%d", name, port)
}

func setup(c *conf, port int) (*http.ServeMux, error) {
  m := http.NewServeMux()

  key, err := newKey()
  if err != nil {
    return nil, err
  }

  cache := Cache{v: map[string]*user{}}

  // setup routes
  oc := oauthConfig(c, port)
  for _, route := range c.Routes {
    host := hostOf(route.From, port)
    m.Handle(fmt.Sprintf("%s/", host), &disp{
      from:   host,
      to:     route.To,
      host:   c.Host,
      domain: c.Oauth.Domain,
      key:    key,
      oauth:  oc,
      cache:  &cache,
    })
  }

  // setup admin
  m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    for _, route := range c.Routes {
      fmt.Fprintf(w, "%s -> %s\n", hostOf(route.From, port), route.To)
    }
  })

  m.HandleFunc(authPathPrefix, func(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    stat := r.FormValue("state")
    if code == "" || stat == "" {
      http.Error(w,
        http.StatusText(http.StatusForbidden),
        http.StatusForbidden)
      return
    }

    // If stat isn't a valid URL, this is totally bogus.
    back, err := url.Parse(stat)
    if err != nil {
      http.Error(w,
        http.StatusText(http.StatusForbidden),
        http.StatusForbidden)
      return
    }

    t := &oauth.Transport{Config: oc}
    _, err = t.Exchange(code)
    if err != nil {
      http.Error(w, "Forbidden", http.StatusForbidden)
      return
    }

    res, err := t.Client().Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
    if err != nil {
      panic(err)
      return
    }
    defer res.Body.Close()

    u := user{}
    if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
      panic(err)
    }

    // this only happens when someone edits the auth url
    if !strings.HasSuffix(u.Email, c.Oauth.Domain) {
      http.Error(w,
        http.StatusText(http.StatusForbidden),
        http.StatusForbidden)
      return
    }

    v, err := u.encode(key)
    if err != nil {
      panic(err)
    }

    // keep this in cache for quick verification
    cache.write(v, &u)

    http.SetCookie(w, &http.Cookie{
      Name:   userCookieKey,
      Value:  url.QueryEscape(v),
      Path:   "/",
      MaxAge: 3600,
    })

    p := back.Path
    if back.RawQuery != "" {
      p += fmt.Sprintf("?%s", back.RawQuery)
    }

    http.Redirect(w, r,
      fmt.Sprintf("http://%s%s?%s", back.Host, authPathPrefix,
        url.Values{
          "p": {p},
          "c": {v},
        }.Encode()),
      http.StatusFound)
  })

  m.HandleFunc(
    fmt.Sprintf("%slogout/", authPathPrefix),
    func(w http.ResponseWriter, r *http.Request) {
      http.SetCookie(w, &http.Cookie{
        Name:   userCookieKey,
        Value:  "",
        Path:   "/",
        MaxAge: 0,
      })

      // TODO(knorton): Convert this to simple html page
      w.Header().Set("Content-Type", "text/plain")
      fmt.Fprintln(w, "ok.")
    })

  return m, nil
}

func addrFrom(port int) string {
  switch port {
  case 80:
    return ":http"
  case 443:
    return ":https"
  }
  return fmt.Sprintf(":%d", port)
}

func main() {
  flagPort := flag.Int("port", 80, "")
  flagConf := flag.String("conf", "underpants.json", "")

  flag.Parse()

  c, err := config(*flagConf)
  if err != nil {
    panic(err)
  }

  m, err := setup(c, *flagPort)
  if err != nil {
    panic(err)
  }

  if err := http.ListenAndServe(addrFrom(*flagPort), m); err != nil {
    panic(err)
  }
}
