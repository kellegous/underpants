package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/auth/google"
	"github.com/kellegous/underpants/auth/okta"
	"github.com/kellegous/underpants/auth/slack"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/hub"
	"github.com/kellegous/underpants/mux"
	"github.com/kellegous/underpants/proxy"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"
)

// getAuthProvider returns the auth.Provider that was configured in the config info.
func getAuthProvider(cfg *config.Info) (auth.Provider, error) {
	var prv auth.Provider

	switch cfg.Oauth.Provider {
	case google.Name, "":
		prv = google.Provider
	case okta.Name:
		prv = okta.Provider
	case slack.Name:
		prv = slack.Provider
	default:
		return nil, fmt.Errorf("invalid oauth provider: %s", cfg.Oauth.Provider)
	}

	if err := prv.Validate(cfg); err != nil {
		return nil, err
	}

	return prv, nil
}

func getAuthProviderName(cfg *config.Info) string {
	switch cfg.Oauth.Provider {
	case google.Name, "":
		return google.Name
	case okta.Name:
		return okta.Name
	case slack.Name:
		return slack.Name
	}
	return "unknown"
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

// buildMux creates a mux for serving all http routes.
func buildMux(ctx *config.Context, p auth.Provider) (*mux.Serve, error) {
	mb := mux.Create()

	// setup routes for proxy backends
	proxy.Setup(ctx, p, mb)

	// setup all routes for the hub
	hub.Setup(ctx, p, mb)

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

func contextFrom(cfg *config.Info, port int) (*config.Context, error) {
	// Construct the HMAC signing key
	key, err := newKey()
	if err != nil {
		return nil, err
	}

	if port == 0 {
		if cfg.HasCerts() {
			port = 443
		} else {
			port = 80
		}
	}

	return config.BuildContext(cfg, port, key), nil
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
		panic(err)
	}

	var cfg config.Info
	if err := cfg.ReadFile(*flagConf); err != nil {
		zap.L().Fatal("unable to load config",
			zap.String("filename", *flagConf),
			zap.Error(err))
	}

	p, err := getAuthProvider(&cfg)
	if err != nil {
		zap.L().Fatal("invalid provider config",
			zap.String("filename", *flagConf),
			zap.Error(err))
	}

	ctx, err := contextFrom(&cfg, *flagPort)
	if err != nil {
		zap.L().Fatal("unable to build context",
			zap.Error(err))
	}

	zap.L().Info("starting",
		zap.Int("port", ctx.Port),
		zap.String("conf", *flagConf),
		zap.String("provider", getAuthProviderName(ctx.Info)))

	m, err := buildMux(ctx, p)
	if err != nil {
		zap.L().Fatal("unable to build mux",
			zap.Error(err))
	}

	if err := ListenAndServe(ctx, m); err != nil {
		zap.L().Fatal("unable to listen and serve",
			zap.Error(err))
	}
}
