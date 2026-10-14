package fetch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/plain" {
			t.Errorf("expected Accept text/plain, got %q", r.Header.Get("Accept"))
		}
		fmt.Fprint(w, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample test@example.com")
	}))
	defer server.Close()

	// httptest NewTLSServer uses https but with a self-signed cert. We must
	// configure the client to skip verification in the test.
	c := NewClient()
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: server.TLS,
	}

	c.httpClient = server.Client()

	body, err := c.Fetch(context.Background(), server.URL+"/keys")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if !strings.Contains(body, "ssh-ed25519") {
		t.Errorf("body missing key: %s", body)
	}
}

func TestFetchRejectsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	c := NewClient()
	_, err := c.Fetch(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "non-https URL") {
		t.Errorf("expected non-https error, got: %v", err)
	}
}

func TestFetchRetriesThenFails(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient()
	c.retries = 2
	c.retryGap = 10 * time.Millisecond
	c.httpClient = server.Client()

	_, err := c.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestFetchContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "late")
	}))
	defer server.Close()

	c := NewClient()
	c.httpClient.Timeout = 5 * time.Second
	c.httpClient = server.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.Fetch(ctx, server.URL)
	if err == nil {
		t.Fatal("expected context error")
	}
}
