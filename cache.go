package oauth2local

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosimple/slug"
	"golang.org/x/oauth2"
)

type cache struct {
	// Invalidate the previous token.
	// InvalidatePrevious bool
	// The location of the token cache.
	// Path string
	// The directory to use for the token cache. Will be used to create path if path is not provided.
	// Dir string
	// The name of the service. Will be used to create path if path is not provided.
	ServiceName string
}

func (c cache) getPath(scopes []string) string {
	// if c.Path != "" {
	// 	return c.Path
	// }

	// if c.Dir == "" {
	// 	c.Dir = os.TempDir()
	dir := os.TempDir()
	// }

	if c.ServiceName == "" {
		return ""
	}

	if len(scopes) == 0 {
		return filepath.Join(dir, c.ServiceName, "token.json")
	}

	return filepath.Join(dir, c.ServiceName,
		fmt.Sprintf("token-with-scopes-%s.json", slug.Make(strings.Join(scopes, "-"))))
}

// writeToken saves a token to a file path.
func writeToken(path string, token *oauth2.Token) error {
	if err := os.MkdirAll(filepath.Dir(path), fs.ModePerm); err != nil {
		return fmt.Errorf("creating token cache directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating token cache: %w", err)
	}
	defer f.Close()

	if err := json.MarshalWrite(f, token); err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	return nil
}

// readToken reads an OAuth2 token from a given file and returns it
func readToken(path string) (*oauth2.Token, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}
	defer f.Close()

	token := &oauth2.Token{}
	if err := json.UnmarshalRead(f, token); err != nil {
		return nil, fmt.Errorf("unmarshaling token: %w", err)
	}

	return token, nil
}
