package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout   = 30 * time.Second
	defaultRetries   = 3
	defaultRetryGap  = 1 * time.Second
	defaultMaxSize   = 5 * 1024 * 1024 // 5 MiB
)

// maxBodySize is the maximum response body the client will read. It can be
// adjusted for tests.
var maxBodySize int64 = defaultMaxSize

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

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				ResponseHeaderTimeout: 10 * time.Second,
			},
		},
		retries:   defaultRetries,
		retryGap:  defaultRetryGap,
		userAgent: "key-daemon/1.0",
	}
}

// redactURL returns a string suitable for logging: the scheme, host, and path
// are preserved, but any userinfo and query values are redacted. Strings
// without a URL scheme are returned unchanged.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// isNonHTTPS reports whether rawURL is not an HTTPS URL. It accepts
// case-insensitive schemes (e.g., HTTPS://example.com).
func isNonHTTPS(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	return !strings.EqualFold(u.Scheme, "https")
}

// Fetch retrieves the body of the given URL as a string.
// Only HTTPS URLs are accepted.
func (c *Client) Fetch(ctx context.Context, rawURL string) (string, error) {
	if isNonHTTPS(rawURL) {
		return "", fmt.Errorf("refusing to fetch non-https URL: %s", redactURL(rawURL))
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

		body, err := c.doFetch(ctx, rawURL)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("fetch %s failed after %d attempts: %w", redactURL(rawURL), c.retries+1, lastErr)
}

func (c *Client) doFetch(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBodySize {
		return "", fmt.Errorf("response exceeds maximum size of %d bytes", maxBodySize)
	}

	return string(data), nil
}
