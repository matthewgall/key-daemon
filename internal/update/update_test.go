package update

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.1", "v1.0.0", false},
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"dev", "v9.9.9", false},
		{"", "v1.0.0", false},
		{"v1.0.0", "", false},
		{"v1.0.0", "v1.0.1-rc1", true},
		{"v1.0.0-beta", "v1.0.1", true},
	}
	for _, tc := range cases {
		got := IsNewer(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestLatestRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("expected Accept header, got %q", r.Header.Get("Accept"))
		}
		fmt.Fprint(w, `{"tag_name":"v9.9.9","html_url":"https://github.com/matthewgall/key-daemon/releases/tag/v9.9.9","draft":false}`)
	}))
	defer server.Close()

	c := NewChecker()
	c.SetAPIURL(server.URL)

	info, err := c.LatestRelease(context.Background())
	if err != nil {
		t.Fatalf("LatestRelease failed: %v", err)
	}
	if info.Version != "v9.9.9" {
		t.Errorf("expected version v9.9.9, got %q", info.Version)
	}
	if info.URL == "" {
		t.Error("expected non-empty URL")
	}
}

func TestLatestReleaseDraftSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v9.9.9","html_url":"https://example.com","draft":true}`)
	}))
	defer server.Close()

	c := NewChecker()
	c.SetAPIURL(server.URL)

	_, err := c.LatestRelease(context.Background())
	if err == nil {
		t.Fatal("expected error for draft release")
	}
}

func TestLatestReleaseNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer server.Close()

	c := NewChecker()
	c.SetAPIURL(server.URL)

	_, err := c.LatestRelease(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
