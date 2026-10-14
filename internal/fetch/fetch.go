package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultTimeout  = 30 * time.Second
	defaultRetries  = 3
	defaultRetryGap = 1 * time.Second
)

// Client fetches text resources over HTTPS with retries.
type Client struct {
	httpClient *http.Client
	retries    int
	retryGap   time.Duration
	userAgent  string
}

// Client returns the underlying HTTP client so callers can configure TLS or timeouts.
func (c *Client) Client() *http.Client {
	return c.httpClient
}

// NewClient creates a fetcher with sensible defaults.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		retries:   defaultRetries,
		retryGap:  defaultRetryGap,
		userAgent: "key-daemon/1.0",
	}
}

// Fetch retrieves the body of the given URL as a string.
// Only HTTPS URLs are accepted.
func (c *Client) Fetch(ctx context.Context, url string) (string, error) {
	if !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("refusing to fetch non-https URL: %s", url)
	}

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(c.retryGap):
			}
		}

		body, err := c.doFetch(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("fetch %s failed after %d attempts: %w", url, c.retries+1, lastErr)
}

func (c *Client) doFetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
