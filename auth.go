package oauth2local

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/oauth2"
)

func GetToken(ctx context.Context, cfg *oauth2.Config, service string) (*oauth2.Token, error) {
	return getTokenWithConfig(ctx, &config{
		cache:           cache{ServiceName: service},
		Oauth2:          cfg,
		AuthCodeOptions: []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
	})
}

// getTokenWithConfig either gets a token from the specified cache location or
// generates a new token by starting a local server that both redirects to the OAuth 2.0 provider's consent page and receives a callback from the provider.
// Upon receiving the callback, it takes the provided code and does a token exchange.
func getTokenWithConfig(ctx context.Context, cfg *config) (*oauth2.Token, error) {
	cacheLoc := cfg.cache.getPath(cfg.Oauth2.Scopes)

	if cacheLoc == "" {
		// do not cache
		return getTokenViaBrowser(ctx, cfg)
	}

	// if cfg.cache.InvalidatePrevious {
	// 	if err := os.Remove(cacheLoc); err != nil && !errors.Is(err, fs.ErrNotExist) {
	// 		return nil, fmt.Errorf("removing previous token: %w", err)
	// 	}

	// 	return getAndCacheNewToken(ctx, cfg, cacheLoc)
	// }

	// Check if the token is cached and valid.
	tkn, err := readToken(cacheLoc)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No cached token.
			return getAndCacheNewToken(ctx, cfg, cacheLoc)
		}

		return nil, err
	}

	if tkn.Valid() {
		// Token is valid, return it.
		return tkn, nil
	}

	if tkn.RefreshToken == "" {
		// Token is invalid and refresh token not set, get new one.
		return getAndCacheNewToken(ctx, cfg, cacheLoc)
	}

	// fmt.Printf("Token in %s is invalid, generating a new one.\n", cacheLoc)

	// Refresh the token.
	tkn, err = cfg.Oauth2.TokenSource(ctx, tkn).Token()
	if err != nil {
		// fmt.Printf("Error refreshing token: %v\n", err)
		return getAndCacheNewToken(ctx, cfg, cacheLoc)
	}

	// Cache the refreshed token.
	if err := writeToken(cacheLoc, tkn); err != nil {
		return nil, err
	}

	return tkn, nil
}

func getAndCacheNewToken(ctx context.Context, cfg *config, cacheLoc string) (*oauth2.Token, error) {
	tkn, err := getTokenViaBrowser(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting token via browser: %w", err)
	}

	return tkn, writeToken(cacheLoc, tkn)
}
