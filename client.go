package oauth2local

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func GetClient(ctx context.Context, cfg *oauth2.Config, service string) (*http.Client, error) {
	tkn, err := GetToken(ctx, cfg, service)
	if err != nil {
		return nil, err
	}

	return cfg.Client(ctx, tkn), nil
}
