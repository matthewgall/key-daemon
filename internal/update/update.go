package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
	githubAPIURL   = "https://api.github.com/repos/matthewgall/key-daemon/releases/latest"
)

// Info describes the latest available release.
type Info struct {
	Version string
	URL     string
}

// Checker queries GitHub Releases for newer versions.
type Checker struct {
	apiURL     string
	httpClient *http.Client
	userAgent  string
}

// NewChecker creates a Checker with sensible defaults.
func NewChecker() *Checker {
	return &Checker{
		apiURL: githubAPIURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		userAgent: "key-daemon/update-check",
	}
}

// SetHTTPClient overrides the HTTP client. Used in tests.
func (c *Checker) SetHTTPClient(client *http.Client) {
	c.httpClient = client
}

// SetAPIURL overrides the GitHub API URL. Used in tests.
func (c *Checker) SetAPIURL(url string) {
	c.apiURL = url
}

// LatestRelease returns information about the latest published release.
func (c *Checker) LatestRelease(ctx context.Context) (*Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1*1024*1024 {
		return nil, fmt.Errorf("release API response exceeds 1 MiB")
	}

	var payload struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Draft   bool   `json:"draft"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse release payload: %w", err)
	}
	if payload.TagName == "" {
		return nil, fmt.Errorf("release payload missing tag_name")
	}
	if payload.Draft {
		return nil, fmt.Errorf("latest release is a draft")
	}

	return &Info{
		Version: payload.TagName,
		URL:     payload.HTMLURL,
	}, nil
}

// IsNewer reports whether latest is newer than current.
// It strips a leading 'v', expects major.minor.patch versions, and ignores
// non-numeric suffixes. Development builds (e.g. "dev") are never newer.
func IsNewer(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if current == "" || current == "dev" {
		return false
	}
	if latest == "" {
		return false
	}
	latestParts := versionParts(latest)
	currentParts := versionParts(current)
	for i := 0; i < 3; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return false
}

// versionParts converts a version string into a comparable triple.
// Non-numeric segments and suffixes are ignored.
func versionParts(s string) [3]int {
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 4)
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		p := parts[i]
		// Strip any non-leading digits (e.g. "1-beta" -> "1").
		idx := 0
		for idx < len(p) && p[idx] >= '0' && p[idx] <= '9' {
			idx++
		}
		if idx == 0 {
			out[i] = 0
			continue
		}
		if v, err := strconv.Atoi(p[:idx]); err == nil {
			out[i] = v
		}
	}
	return out
}
