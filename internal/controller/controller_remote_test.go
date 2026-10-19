package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hiddeco/sshsig"
	"github.com/matthewgall/key-daemon/internal/config"
	"github.com/matthewgall/key-daemon/internal/logger"
	"golang.org/x/crypto/ssh"
)

func TestFetchRemoteConfigWithSignature(t *testing.T) {
	data := []byte("interval: 5m\n")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	sig, err := sshsig.Sign(bytes.NewReader(data), signer, sshsig.HashSHA512, "key-daemon")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/config.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	})
	mux.HandleFunc("/config.yaml.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(sshsig.Armor(sig))
	})

	rc := config.RemoteConfig{
		URL:          server.URL + "/config.yaml",
		SignatureURL: server.URL + "/config.yaml.sig",
		PublicKey:    string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}

	ctrl := &Controller{remoteClient: server.Client()}
	got, err := ctrl.fetchRemoteConfig(context.Background(), rc)
	if err != nil {
		t.Fatalf("fetchRemoteConfig: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("fetched data mismatch: got %q", got)
	}
}

func TestFetchRemoteConfigWithBadSignature(t *testing.T) {
	data := []byte("interval: 5m\n")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatalf("create other signer: %v", err)
	}

	sig, err := sshsig.Sign(bytes.NewReader(data), otherSigner, sshsig.HashSHA512, "key-daemon")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/config.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	})
	mux.HandleFunc("/config.yaml.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sshsig.Armor(sig))
	})

	rc := config.RemoteConfig{
		URL:          server.URL + "/config.yaml",
		SignatureURL: server.URL + "/config.yaml.sig",
		PublicKey:    string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}

	ctrl := &Controller{remoteClient: server.Client()}
	_, err = ctrl.fetchRemoteConfig(context.Background(), rc)
	if err == nil {
		t.Fatal("expected verification error for bad signature")
	}
}

func TestRemoteConfigPullDryRun(t *testing.T) {
	remoteData := []byte("interval: 2m\nvalidate: true\n")

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	mux.HandleFunc("/config.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(remoteData)
	})

	dir := t.TempDir()
	localPath := filepath.Join(dir, "config.yaml")
	localContent := fmt.Sprintf("interval: 5m\nvalidate: true\nremote_config:\n  url: %s/config.yaml\n  interval: 5m\n", server.URL)
	if err := os.WriteFile(localPath, []byte(localContent), 0o644); err != nil {
		t.Fatalf("write local config: %v", err)
	}

	ctrl := New(localPath, logger.New(logger.ErrorLevel), "dev")
	ctrl.remoteClient = server.Client()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ctrl.RemoteConfigPull(context.Background(), true)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("RemoteConfigPull dry-run: %v", err)
	}

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "would write") {
		t.Errorf("expected dry-run output, got %q", string(out))
	}

	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("read local config: %v", err)
	}
	if string(got) != localContent {
		t.Errorf("local config was modified during dry-run")
	}
}
