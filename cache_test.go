package oauth2local

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestWriteReadToken(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "my-token.json")

	for _, token := range []*oauth2.Token{
		{},
		{AccessToken: "foo"},
		{AccessToken: "bar"},
	} {
		if err := writeToken(path, token); err != nil {
			t.Fatal(err)
		}

		got, err := readToken(path)
		if err != nil {
			t.Fatal(err)
		}

		if token.AccessToken != got.AccessToken {
			t.Fatalf("want: %q, got: %q", token.AccessToken, got.AccessToken)
		}
	}
}

func TestWriteReadTokenFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "dir", "token.json")
	want := &oauth2.Token{
		AccessToken:  "access",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	if err := writeToken(path, want); err != nil {
		t.Fatal(err)
	}

	got, err := readToken(path)
	if err != nil {
		t.Fatal(err)
	}

	if got.AccessToken != want.AccessToken || got.TokenType != want.TokenType ||
		got.RefreshToken != want.RefreshToken || !got.Expiry.Equal(want.Expiry) {
		t.Fatalf("want %+v, got %+v", want, got)
	}
}

func TestReadTokenMissing(t *testing.T) {
	t.Parallel()

	// getTokenWithConfig relies on this to tell a missing cache from a broken one.
	if _, err := readToken(filepath.Join(t.TempDir(), "absent.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want %v, got %v", fs.ErrNotExist, err)
	}
}

func TestWriteTokenUnwritable(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	err := writeToken(filepath.Join(blocker, "token.json"), &oauth2.Token{})
	if err == nil || !strings.HasPrefix(err.Error(), "creating token cache directory: ") {
		t.Fatalf("unexpected error: %v", err)
	}

	err = writeToken(t.TempDir(), &oauth2.Token{})
	if err == nil || !strings.HasPrefix(err.Error(), "creating token cache: ") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCacheGetPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	for _, tc := range []struct {
		name    string
		service string
		scopes  []string
		want    string
	}{
		{name: "no service", scopes: []string{"read"}, want: ""},
		{name: "no scopes", service: "svc", want: filepath.Join(dir, "svc", "token.json")},
		{
			name:    "scopes",
			service: "svc",
			scopes:  []string{"https://www.googleapis.com/auth/calendar", "Email"},
			want:    filepath.Join(dir, "svc", "token-with-scopes-https-www-googleapis-com-auth-calendar-email.json"),
		},
	} {
		if got := (cache{ServiceName: tc.service}).getPath(tc.scopes); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}
