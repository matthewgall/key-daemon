package sources

import (
	"context"
	"fmt"
	"strings"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/fetch"
)

// Provider fetches raw authorized_keys text for a source.
type Provider struct {
	fetcher *fetch.Client
}

// NewProvider creates a Provider using the given fetch client.
func NewProvider(fetcher *fetch.Client) *Provider {
	return &Provider{fetcher: fetcher}
}

// Resolve translates a config source into a fetchable HTTPS URL.
func Resolve(src config.Source) (string, error) {
	switch src.Type {
	case "url":
		if !strings.HasPrefix(src.Value, "https://") {
			return "", fmt.Errorf("url source must use https://")
		}
		return src.Value, nil
	case "github":
		return fmt.Sprintf("https://github.com/%s.keys", src.Value), nil
	case "sshid":
		return fmt.Sprintf("https://sshid.io/%s", src.Value), nil
	case "gitlab":
		return fmt.Sprintf("https://gitlab.com/%s.keys", src.Value), nil
	default:
		return "", fmt.Errorf("unsupported source type %q", src.Type)
	}
}

// Fetch returns the raw key text for a single source.
func (p *Provider) Fetch(ctx context.Context, src config.Source) (string, error) {
	url, err := Resolve(src)
	if err != nil {
		return "", err
	}
	return p.fetcher.Fetch(ctx, url)
}

// FetchAll merges key text from multiple sources, separated by blank lines.
func (p *Provider) FetchAll(ctx context.Context, sources []config.Source) (string, error) {
	var parts []string
	for _, src := range sources {
		text, err := p.Fetch(ctx, src)
		if err != nil {
			return "", fmt.Errorf("source %s:%s: %w", src.Type, src.Value, err)
		}
		parts = append(parts, strings.TrimSpace(text))
	}
	return strings.Join(parts, "\n\n"), nil
}
