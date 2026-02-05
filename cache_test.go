package oauth2local

import (
	"path/filepath"
	"testing"

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
