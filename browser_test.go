package oauth2local

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testClientID     = "client-id"
	testClientSecret = "client-secret"
	testCode         = "the-code"
)

// provider is a fake OAuth 2.0 authorization server.
type provider struct {
	*httptest.Server

	// Set before use: the error the consent page reports instead of a code.
	denyWith string
	// Set before use: whether the token endpoint rejects refresh tokens.
	rejectRefresh bool

	mu          sync.Mutex
	authQueries []url.Values
	tokenForms  []url.Values
	basicAuthOK bool
}

func newProvider(t *testing.T) *provider {
	t.Helper()

	p := &provider{}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)

	return p
}

func (p *provider) config(scopes ...string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.URL + "/authorize",
			TokenURL:  p.URL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: scopes,
	}
}

func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	p.mu.Lock()
	p.authQueries = append(p.authQueries, q)
	p.mu.Unlock()

	callback, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	params := url.Values{"state": {q.Get("state")}}
	if p.denyWith != "" {
		params.Set("error", p.denyWith)
		params.Set("error_description", "the user said no")
	} else {
		params.Set("code", testCode)
	}

	callback.RawQuery = params.Encode()
	http.Redirect(w, r, callback.String(), http.StatusFound)
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, pass, ok := r.BasicAuth()

	p.mu.Lock()
	p.tokenForms = append(p.tokenForms, r.PostForm)
	p.basicAuthOK = ok && user == testClientID && pass == testClientSecret
	p.mu.Unlock()

	var accessToken string

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if r.PostForm.Get("code") != testCode {
			writeTokenError(w)
			return
		}

		accessToken = "from-code"
	case "refresh_token":
		if p.rejectRefresh {
			writeTokenError(w)
			return
		}

		accessToken = "from-refresh-" + r.PostForm.Get("refresh_token")
	default:
		writeTokenError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"refresh_token": "new-refresh",
		"expires_in":    3600,
	})
}

func writeTokenError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
}

func (p *provider) requests() (auth, token []url.Values) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]url.Values(nil), p.authQueries...), append([]url.Values(nil), p.tokenForms...)
}

// visit fetches u like a browser would, following redirects.
func visit(u string) (int, string, error) {
	res, err := http.Get(u) //nolint:noctx
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	return res.StatusCode, string(body), err
}

// fakeBrowser records what a user's browser sees when sent to the local server.
type fakeBrowser struct {
	mu       sync.Mutex
	opened   []string
	status   int
	body     string
	visitErr error
}

func (b *fakeBrowser) open(authURL string) error {
	status, body, err := visit(authURL)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.opened = append(b.opened, authURL)
	b.status, b.body, b.visitErr = status, body, err

	return nil
}

func testConfig(cfg *oauth2.Config, service string, openBrowser func(string) error) *config {
	c := newConfig(cfg, service)
	c.port = "0"
	c.openBrowser = openBrowser

	return c
}

func TestNewConfig(t *testing.T) {
	t.Parallel()

	oc := &oauth2.Config{ClientID: testClientID}
	c := newConfig(oc, "svc")

	if c.Oauth2 != oc || c.cache.ServiceName != "svc" || c.port != defaultPort || c.openBrowser == nil {
		t.Fatalf("unexpected config: %+v", c)
	}

	u, err := url.Parse(oc.AuthCodeURL("s", c.AuthCodeOptions...))
	if err != nil {
		t.Fatal(err)
	}

	if got := u.Query().Get("access_type"); got != "offline" {
		t.Fatalf("access_type: want %q, got %q", "offline", got)
	}
}

func TestGetTokenViaBrowser(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	oc := p.config("read", "write")
	b := &fakeBrowser{}

	tkn, err := getTokenViaBrowser(t.Context(), testConfig(oc, "", b.open))
	if err != nil {
		t.Fatal(err)
	}

	if tkn.AccessToken != "from-code" || tkn.RefreshToken != "new-refresh" {
		t.Fatalf("unexpected token: %+v", tkn)
	}

	if !strings.HasPrefix(oc.RedirectURL, "http://localhost:") || !strings.HasSuffix(oc.RedirectURL, "/callback") {
		t.Fatalf("unexpected redirect URL: %q", oc.RedirectURL)
	}

	if len(b.opened) != 1 || b.opened[0] != strings.TrimSuffix(oc.RedirectURL, "/callback")+"/auth" {
		t.Fatalf("browser opened %v, redirect URL is %q", b.opened, oc.RedirectURL)
	}

	if b.visitErr != nil || b.status != http.StatusOK || b.body != string(successHTML) {
		t.Fatalf("browser saw %d %q (error %v)", b.status, b.body, b.visitErr)
	}

	auth, token := p.requests()
	if len(auth) != 1 {
		t.Fatalf("want one consent request, got %d", len(auth))
	}

	for key, want := range map[string]string{
		"client_id":     testClientID,
		"redirect_uri":  oc.RedirectURL,
		"response_type": "code",
		"scope":         "read write",
		"access_type":   "offline",
	} {
		if got := auth[0].Get(key); got != want {
			t.Errorf("consent request %s: want %q, got %q", key, want, got)
		}
	}

	if auth[0].Get("state") == "" {
		t.Error("consent request has no state")
	}

	if len(token) != 1 {
		t.Fatalf("want one token request, got %d", len(token))
	}

	if got := token[0].Get("code"); got != testCode {
		t.Errorf("token request code: want %q, got %q", testCode, got)
	}

	if got := token[0].Get("redirect_uri"); got != oc.RedirectURL {
		t.Errorf("token request redirect_uri: want %q, got %q", oc.RedirectURL, got)
	}

	if !p.basicAuthOK {
		t.Error("token request did not authenticate the client")
	}
}

func TestGetTokenViaBrowserAuthRedirect(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	oc := p.config()

	var (
		status   int
		location string
		reqErr   error
	)

	openBrowser := func(authURL string) error {
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}

		res, err := client.Get(authURL) //nolint:noctx
		if err != nil {
			reqErr = err
			return nil
		}

		_ = res.Body.Close()
		status, location = res.StatusCode, res.Header.Get("Location")

		_, _, reqErr = visit(location)

		return nil
	}

	if _, err := getTokenViaBrowser(t.Context(), testConfig(oc, "", openBrowser)); err != nil {
		t.Fatal(err)
	}

	if reqErr != nil {
		t.Fatal(reqErr)
	}

	// A permanent redirect would be cached by the browser along with its one-time state.
	if status != http.StatusTemporaryRedirect {
		t.Fatalf("want status %d, got %d", http.StatusTemporaryRedirect, status)
	}

	if !strings.HasPrefix(location, p.URL+"/authorize?") {
		t.Fatalf("unexpected location: %q", location)
	}
}

func TestGetTokenViaBrowserInvalidState(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	oc := p.config()

	var (
		forgedStatus int
		forgedBody   string
		forgedErr    error
		b            fakeBrowser
	)

	openBrowser := func(authURL string) error {
		forgedStatus, forgedBody, forgedErr = visit(oc.RedirectURL + "?state=forged&code=evil")
		return b.open(authURL)
	}

	tkn, err := getTokenViaBrowser(t.Context(), testConfig(oc, "", openBrowser))
	if err != nil {
		t.Fatal(err)
	}

	if forgedErr != nil || forgedStatus != http.StatusBadRequest || forgedBody != "invalid state: forged" {
		t.Fatalf("forged callback got %d %q (error %v)", forgedStatus, forgedBody, forgedErr)
	}

	if tkn.AccessToken != "from-code" {
		t.Fatalf("unexpected token: %+v", tkn)
	}

	if _, token := p.requests(); len(token) != 1 || token[0].Get("code") != testCode {
		t.Fatalf("want only the genuine code exchanged, got %v", token)
	}
}

func TestGetTokenViaBrowserDenied(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	p.denyWith = "access_denied"
	b := &fakeBrowser{}

	_, err := getTokenViaBrowser(t.Context(), testConfig(p.config(), "", b.open))
	if err == nil || err.Error() != "authorization failed: access_denied: the user said no" {
		t.Fatalf("unexpected error: %v", err)
	}

	if b.status != http.StatusBadRequest || !strings.Contains(b.body, "access_denied") {
		t.Fatalf("browser saw %d %q", b.status, b.body)
	}

	if _, token := p.requests(); len(token) != 0 {
		t.Fatalf("want no token request, got %v", token)
	}
}

func TestGetTokenViaBrowserExchangeFails(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	oc := p.config()

	openBrowser := func(string) error {
		_, _, _ = visit(oc.RedirectURL + "?" + url.Values{
			"state": {stateFromAuthURL(t, oc)},
			"code":  {"wrong-code"},
		}.Encode())

		return nil
	}

	_, err := getTokenViaBrowser(t.Context(), testConfig(oc, "", openBrowser))

	var rErr *oauth2.RetrieveError
	if !errors.As(err, &rErr) || !strings.HasPrefix(err.Error(), "exchanging token: ") {
		t.Fatalf("unexpected error: %v", err)
	}

	if rErr.ErrorCode != "invalid_grant" {
		t.Fatalf("want error code %q, got %q", "invalid_grant", rErr.ErrorCode)
	}
}

// stateFromAuthURL reads the state the local server expects by asking the provider's consent page.
func stateFromAuthURL(t *testing.T, oc *oauth2.Config) string {
	t.Helper()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	authURL := strings.TrimSuffix(oc.RedirectURL, "/callback") + "/auth"

	res, err := client.Get(authURL) //nolint:noctx
	if err != nil {
		t.Error(err)
		return ""
	}

	_ = res.Body.Close()

	u, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Error(err)
		return ""
	}

	return u.Query().Get("state")
}

func TestGetTokenViaBrowserOpenFails(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	b := &fakeBrowser{}

	// The user can still follow the printed link when no browser opens.
	openBrowser := func(authURL string) error {
		go func() { _ = b.open(authURL) }()
		return errors.New("no browser")
	}

	tkn, err := getTokenViaBrowser(t.Context(), testConfig(p.config(), "", openBrowser))
	if err != nil {
		t.Fatal(err)
	}

	if tkn.AccessToken != "from-code" {
		t.Fatalf("unexpected token: %+v", tkn)
	}
}

func TestGetTokenViaBrowserRepeatedCallback(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	oc := p.config()

	var (
		statuses []int
		errs     []error
	)

	openBrowser := func(string) error {
		u := oc.RedirectURL + "?" + url.Values{"state": {stateFromAuthURL(t, oc)}, "code": {testCode}}.Encode()
		client := &http.Client{Timeout: 2 * time.Second}

		for range 2 {
			res, err := client.Get(u) //nolint:noctx
			if err != nil {
				errs = append(errs, err)
				continue
			}

			_ = res.Body.Close()
			statuses = append(statuses, res.StatusCode)
		}

		return nil
	}

	if _, err := getTokenViaBrowser(t.Context(), testConfig(oc, "", openBrowser)); err != nil {
		t.Fatal(err)
	}

	if len(errs) != 0 || len(statuses) != 2 || statuses[0] != http.StatusOK || statuses[1] != http.StatusOK {
		t.Fatalf("callbacks got %v (errors %v)", statuses, errs)
	}

	if _, token := p.requests(); len(token) != 1 {
		t.Fatalf("want one token request, got %d", len(token))
	}
}

func TestGetTokenViaBrowserContextCanceled(t *testing.T) {
	t.Parallel()

	p := newProvider(t)
	ctx, cancel := context.WithCancel(t.Context())

	openBrowser := func(string) error {
		cancel()
		return nil
	}

	_, err := getTokenViaBrowser(ctx, testConfig(p.config(), "", openBrowser))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want %v, got %v", context.Canceled, err)
	}
}

func TestGetTokenViaBrowserPortInUse(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(newProvider(t).config(), "", func(string) error {
		t.Error("browser opened without a server")
		return nil
	})
	cfg.port = port

	if _, err := getTokenViaBrowser(t.Context(), cfg); err == nil || !strings.HasPrefix(err.Error(), "starting local server: ") {
		t.Fatalf("unexpected error: %v", err)
	}
}
