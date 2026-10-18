package sysinfo

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchExternalIPPlainText(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.42\n"))
	}))
	defer ts.Close()

	ip, err := FetchExternalIP(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("FetchExternalIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.42")) {
		t.Errorf("got %v, want 203.0.113.42", ip)
	}
}

func TestFetchExternalIPJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"203.0.113.42","country":"GB"}`))
	}))
	defer ts.Close()

	ip, err := FetchExternalIP(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("FetchExternalIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.42")) {
		t.Errorf("got %v, want 203.0.113.42", ip)
	}
}

func TestFetchExternalIPEmptyURL(t *testing.T) {
	ip, err := FetchExternalIP(context.Background(), nil, "")
	if err != nil {
		t.Fatalf("FetchExternalIP: %v", err)
	}
	if ip != nil {
		t.Errorf("expected nil IP for empty URL, got %v", ip)
	}
}
