package oauth2local

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

const (
	authPath        = "/auth"
	timeoutDuration = 5 * time.Minute
)

var (
	rePort = regexp.MustCompile(`^http://localhost:([0-9]+)`)

	//go:embed success.html
	successHTML []byte
)

type config struct {
	// The port to use for the local server.
	// Port string
	// The OAuth 2.0 configuration.
	Oauth2 *oauth2.Config
	// The cache configuration.
	cache cache
	// The options to pass to the AuthCodeURL method.
	AuthCodeOptions []oauth2.AuthCodeOption
	// The options to pass to the Exchange method.
	// ExchangeOptions []oauth2.AuthCodeOption
	// A verification file to serve at the root of the local server.
	// VerificationFile *VerificationFile
}

// getTokenViaBrowser generates a new token by starting a local server that both redirects to the OAuth 2.0 provider's consent page and receives a callback from the provider.
// Upon receiving the callback, it takes the provided code and does a token exchange.
func getTokenViaBrowser(ctx context.Context, cfg *config) (*oauth2.Token, error) {
	// if cfg.Port == "" {
	// Get the port from the redirect URL.
	match := rePort.FindStringSubmatch(cfg.Oauth2.RedirectURL)
	if len(match) == 0 {
		return nil, fmt.Errorf("port not provided, can't infer from redirect URL %q",
			cfg.Oauth2.RedirectURL)
	}

	// cfg.Port = match[1]
	port := match[1]
	// } else if cfg.Oauth2.RedirectURL == "" {
	// Set the redirect URL to the port.
	// 	cfg.Oauth2.RedirectURL = fmt.Sprintf("http://localhost:%s/callback", cfg.Port)
	// }

	baseURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%s", port)}

	redirectURL, err := url.Parse(cfg.Oauth2.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redirect URL: %w", err)
	}

	callbackPath := redirectURL.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	// Generate the authentication URL.
	state := uuid.NewString()
	authCodeURL := cfg.Oauth2.AuthCodeURL(state, cfg.AuthCodeOptions...)

	mux := http.NewServeMux()
	svr := &http.Server{Addr: ":" + port, Handler: mux}

	// The authentication path should redirect to the OAuth 2.0 provider's consent page.
	// NOTE: If the redirect is permanent, it will be cached which we don't want, so it is a temporary redirect.
	mux.HandleFunc(authPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	})

	codeCh := make(chan string)
	defer close(codeCh)

	// The callback path checks if the state is valid.
	// If so, we retrieve the code.
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if gotState := r.URL.Query().Get("state"); state != gotState {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid state: "))
			w.Write([]byte(gotState))
			return
		}

		codeCh <- r.URL.Query().Get("code")

		w.Write(successHTML)
	})

	// if fi := cfg.VerificationFile; fi != nil {
	// 	mux.HandleFunc(fmt.Sprintf("/%s", fi.Path), func(w http.ResponseWriter, r *http.Request) {
	// 		w.Write(fi.Content)
	// 	})
	// }

	svr.RegisterOnShutdown(func() { slog.DebugContext(ctx, "server shut down") })

	authURL := baseURL.JoinPath(authPath).String()
	go func() {
		fmt.Printf(`Starting server, please visit %q to be redirected to the OAuth 2.0 provider's consent page.
Please make sure %s is an allowed callback URL.
`, authURL, cfg.Oauth2.RedirectURL)
		_ = browser.OpenURL(authURL)
		// if cfg.VerificationFile != nil {
		// 	fmt.Printf("Serving verification file at %q\n", baseURL.JoinPath(cfg.VerificationFile.Path))
		// }

		_ = svr.ListenAndServe()
	}()
	defer svr.Shutdown(ctx)

	select {
	case code := <-codeCh:
		tkn, err := cfg.Oauth2.Exchange(ctx, code) // cfg.ExchangeOptions...,
		if err != nil {
			return nil, fmt.Errorf("exchanging token: %w", err)
		}

		return tkn, nil
	case <-time.After(timeoutDuration):
		return nil, errors.New("token exchange timed out")
	}
}
