package oauth2local

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

const (
	authPath        = "/auth"
	callbackPath    = "/callback"
	defaultPort     = "8080"
	timeoutDuration = 5 * time.Minute
)

//go:embed success.html
var successHTML []byte

type config struct {
	// The OAuth 2.0 configuration.
	Oauth2 *oauth2.Config
	// The cache configuration.
	cache cache
	// The options to pass to the AuthCodeURL method.
	AuthCodeOptions []oauth2.AuthCodeOption
	// The port of the local server; "0" picks a free one.
	port string
	// Opens the given URL in the user's browser.
	openBrowser func(url string) error
}

func newConfig(cfg *oauth2.Config, service string) *config {
	return &config{
		cache:           cache{ServiceName: service},
		Oauth2:          cfg,
		AuthCodeOptions: []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
		port:            defaultPort,
		openBrowser:     browser.OpenURL,
	}
}

// getTokenViaBrowser generates a new token by starting a local server that both redirects to the OAuth 2.0 provider's consent page and receives a callback from the provider.
// Upon receiving the callback, it takes the provided code and does a token exchange.
func getTokenViaBrowser(ctx context.Context, cfg *config) (*oauth2.Token, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("localhost", cfg.port))
	if err != nil {
		return nil, fmt.Errorf("starting local server: %w", err)
	}

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()

		return nil, fmt.Errorf("reading local server port: %w", err)
	}

	baseURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("localhost", port)}
	cfg.Oauth2.RedirectURL = baseURL.JoinPath(callbackPath).String()

	// Generate the authentication URL.
	state := uuid.NewString()
	authCodeURL := cfg.Oauth2.AuthCodeURL(state, cfg.AuthCodeOptions...)

	mux := http.NewServeMux()
	svr := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// NOTE: If the redirect is permanent, it will be cached which we don't want, so it is a temporary redirect.
	mux.HandleFunc(authPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	})

	// Only the first valid callback counts; later ones must not block.
	resultCh := make(chan callbackResult, 1)

	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if gotState := q.Get("state"); state != gotState {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid state: "))
			_, _ = w.Write([]byte(gotState))

			return
		}

		res := callbackResult{code: q.Get("code")}
		if e := q.Get("error"); e != "" {
			res.err = fmt.Errorf("authorization failed: %s", e)
			if desc := q.Get("error_description"); desc != "" {
				res.err = fmt.Errorf("%w: %s", res.err, desc)
			}
		}

		select {
		case resultCh <- res:
		default:
		}

		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(res.err.Error()))

			return
		}

		_, _ = w.Write(successHTML)
	})

	svr.RegisterOnShutdown(func() { slog.DebugContext(ctx, "server shut down") })

	go func() { _ = svr.Serve(ln) }()

	defer func() {
		if err := svr.Shutdown(context.WithoutCancel(ctx)); err != nil {
			slog.ErrorContext(ctx, "shutting down server", "error", err)
		}
	}()

	authURL := baseURL.JoinPath(authPath).String()
	fmt.Printf(`Starting server, please visit %q to be redirected to the OAuth 2.0 provider's consent page.
Please make sure %s is an allowed callback URL.
`, authURL, cfg.Oauth2.RedirectURL)

	if err := cfg.openBrowser(authURL); err != nil {
		slog.WarnContext(ctx, "opening browser", "error", err)
	}

	timer := time.NewTimer(timeoutDuration)
	defer timer.Stop()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}

		tkn, err := cfg.Oauth2.Exchange(ctx, res.code)
		if err != nil {
			return nil, fmt.Errorf("exchanging token: %w", err)
		}

		return tkn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("token exchange timed out")
	}
}

type callbackResult struct {
	code string
	err  error
}
