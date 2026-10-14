package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/fetch"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		src  config.Source
		want string
	}{
		{config.Source{Type: "url", Value: "https://example.com/keys"}, "https://example.com/keys"},
		{config.Source{Type: "github", Value: "matthewgall"}, "https://github.com/matthewgall.keys"},
		{config.Source{Type: "sshid", Value: "matthewgall"}, "https://sshid.io/matthewgall"},
	}

	for _, tt := range tests {
		got, err := Resolve(tt.src)
		if err != nil {
			t.Errorf("Resolve(%+v) error: %v", tt.src, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Resolve(%+v) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestResolveRejectsNonHTTPSURL(t *testing.T) {
	_, err := Resolve(config.Source{Type: "url", Value: "http://example.com/keys"})
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("expected https error, got: %v", err)
	}
}

func TestResolveUnsupportedType(t *testing.T) {
	_, err := Resolve(config.Source{Type: "gitlab", Value: "matthewgall"})
	if err == nil || !strings.Contains(err.Error(), "unsupported source type") {
		t.Errorf("expected unsupported type error, got: %v", err)
	}
}

func TestFetchAll(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			fmt.Fprintln(w, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBase base@example.com")
		case "/matthewgall.keys":
			fmt.Fprintln(w, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGithub github@example.com")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := fetch.NewClient()
	fetcher.Client().Transport = server.Client().Transport

	provider := NewProvider(fetcher)

	sources := []config.Source{
		{Type: "url", Value: server.URL + "/keys"},
		{Type: "url", Value: server.URL + "/matthewgall.keys"},
	}

	body, err := provider.FetchAll(context.Background(), sources)
	if err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}

	if !strings.Contains(body, "Base") || !strings.Contains(body, "Github") {
		t.Errorf("merged body missing expected keys: %s", body)
	}
}

func TestFetchAllStopsOnError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()

	fetcher := fetch.NewClient()
	fetcher.Client().Transport = server.Client().Transport

	provider := NewProvider(fetcher)

	_, err := provider.FetchAll(context.Background(), []config.Source{
		{Type: "url", Value: server.URL + "/keys"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
