package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hiddeco/sshsig"
	"github.com/matthewgall/key-daemon/internal/config"
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
