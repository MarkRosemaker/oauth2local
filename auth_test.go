package oauth2local

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// useTempCache points the token cache at a fresh directory.
func useTempCache(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	return dir
}

func noBrowser(t *testing.T) func(string) error {
	t.Helper()

	return func(string) error {
		t.Error("browser opened")
		return nil
	}
}

func TestGetTokenCachesNewToken(t *testing.T) {
	dir := useTempCache(t)
	p := newProvider(t)
	oc := p.config("read")
	b := &fakeBrowser{}

	first, err := getTokenWithConfig(t.Context(), testConfig(oc, "svc", b.open))
	if err != nil {
		t.Fatal(err)
	}

	cached, err := readToken(filepath.Join(dir, "svc", "token-with-scopes-read.json"))
	if err != nil {
		t.Fatal(err)
	}

	if cached.AccessToken != first.AccessToken || cached.RefreshToken != first.RefreshToken {
		t.Fatalf("cached %+v, returned %+v", cached, first)
	}

	second, err := getTokenWithConfig(t.Context(), testConfig(oc, "svc", noBrowser(t)))
	if err != nil {
		t.Fatal(err)
	}

	if second.AccessToken != first.AccessToken {
		t.Fatalf("want cached %q, got %q", first.AccessToken, second.AccessToken)
	}

	if _, token := p.requests(); len(token) != 1 {
		t.Fatalf("want one token request, got %d", len(token))
	}
}

func TestGetTokenWithoutServiceDoesNotCache(t *testing.T) {
	dir := useTempCache(t)
	p := newProvider(t)
	b := &fakeBrowser{}

	if _, err := getTokenWithConfig(t.Context(), testConfig(p.config(), "", b.open)); err != nil {
		t.Fatal(err)
	}

	if len(b.opened) != 1 {
		t.Fatalf("want browser opened once, got %d", len(b.opened))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf("want empty cache directory, got %v", entries)
	}
}

func TestGetTokenExpired(t *testing.T) {
	expired := time.Now().Add(-time.Hour)

	for _, tc := range []struct {
		name          string
		cached        *oauth2.Token
		rejectRefresh bool
		wantAccess    string
		wantBrowser   bool
	}{
		{
			name:       "refreshed",
			cached:     &oauth2.Token{AccessToken: "old", RefreshToken: "r1", Expiry: expired},
			wantAccess: "from-refresh-r1",
		},
		{
			name:          "refresh rejected",
			cached:        &oauth2.Token{AccessToken: "old", RefreshToken: "r1", Expiry: expired},
			rejectRefresh: true,
			wantAccess:    "from-code",
			wantBrowser:   true,
		},
		{
			name:        "no refresh token",
			cached:      &oauth2.Token{AccessToken: "old", Expiry: expired},
			wantAccess:  "from-code",
			wantBrowser: true,
		},
		{
			name:        "no access token",
			cached:      &oauth2.Token{},
			wantAccess:  "from-code",
			wantBrowser: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := useTempCache(t)
			path := filepath.Join(dir, "svc", "token.json")

			if err := writeToken(path, tc.cached); err != nil {
				t.Fatal(err)
			}

			p := newProvider(t)
			p.rejectRefresh = tc.rejectRefresh
			b := &fakeBrowser{}

			tkn, err := getTokenWithConfig(t.Context(), testConfig(p.config(), "svc", b.open))
			if err != nil {
				t.Fatal(err)
			}

			if tkn.AccessToken != tc.wantAccess {
				t.Fatalf("want access token %q, got %q", tc.wantAccess, tkn.AccessToken)
			}

			if opened := len(b.opened) == 1; opened != tc.wantBrowser {
				t.Fatalf("want browser opened %v, got %v", tc.wantBrowser, b.opened)
			}

			cached, err := readToken(path)
			if err != nil {
				t.Fatal(err)
			}

			if cached.AccessToken != tc.wantAccess || !cached.Valid() {
				t.Fatalf("cache not updated: %+v", cached)
			}
		})
	}
}

func TestGetTokenCorruptCache(t *testing.T) {
	dir := useTempCache(t)
	path := filepath.Join(dir, "svc", "token.json")

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := getTokenWithConfig(t.Context(), testConfig(newProvider(t).config(), "svc", noBrowser(t)))
	if err == nil || !strings.HasPrefix(err.Error(), "unmarshaling token: ") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetTokenBrowserFailsLeavesNoCache(t *testing.T) {
	dir := useTempCache(t)
	p := newProvider(t)
	p.denyWith = "access_denied"
	b := &fakeBrowser{}

	_, err := getTokenWithConfig(t.Context(), testConfig(p.config(), "svc", b.open))
	if err == nil || !strings.HasPrefix(err.Error(), "getting token via browser: authorization failed") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "svc", "token.json")); !os.IsNotExist(err) {
		t.Fatalf("want no cached token, got %v", err)
	}
}

func TestGetClientUsesCachedToken(t *testing.T) {
	dir := useTempCache(t)

	cached := &oauth2.Token{AccessToken: "cached", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
	if err := writeToken(filepath.Join(dir, "svc", "token.json"), cached); err != nil {
		t.Fatal(err)
	}

	gotAuth := make(chan string, 1)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth <- r.Header.Get("Authorization")
	}))
	defer api.Close()

	client, err := GetClient(t.Context(), newProvider(t).config(), "svc")
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Get(api.URL) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()

	if got := <-gotAuth; got != "Bearer cached" {
		t.Fatalf("want %q, got %q", "Bearer cached", got)
	}
}

func TestGetClientError(t *testing.T) {
	dir := useTempCache(t)
	path := filepath.Join(dir, "svc", "token.json")

	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}

	// A directory in place of the cache is an error, not a missing token.
	client, err := GetClient(t.Context(), newProvider(t).config(), "svc")
	if err == nil || client != nil {
		t.Fatalf("want error and no client, got %v, %v", client, err)
	}
}
