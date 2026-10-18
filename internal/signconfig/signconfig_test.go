package signconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateKey(t *testing.T) ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create ssh signer: %v", err)
	}
	return signer
}

func TestRoundTrip(t *testing.T) {
	signer := generateKey(t)
	data := []byte("hello, remote config")

	var buf bytes.Buffer
	if err := SignTo(signer, data, SignerOptions{}, &buf); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if err := Verify(data, buf.Bytes(), signer.PublicKey(), VerifyOptions{}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTamperedData(t *testing.T) {
	signer := generateKey(t)
	data := []byte("hello, remote config")

	var buf bytes.Buffer
	if err := SignTo(signer, data, SignerOptions{}, &buf); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if err := Verify([]byte("tampered"), buf.Bytes(), signer.PublicKey(), VerifyOptions{}); err == nil {
		t.Fatal("expected verification to fail for tampered data")
	}
}

func TestNamespaceMismatch(t *testing.T) {
	signer := generateKey(t)
	data := []byte("hello, remote config")

	var buf bytes.Buffer
	if err := SignTo(signer, data, SignerOptions{Namespace: "key-daemon"}, &buf); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if err := Verify(data, buf.Bytes(), signer.PublicKey(), VerifyOptions{Namespace: "other"}); err == nil {
		t.Fatal("expected verification to fail for wrong namespace")
	}
}

func TestWrongKey(t *testing.T) {
	signer := generateKey(t)
	other := generateKey(t)
	data := []byte("hello, remote config")

	var buf bytes.Buffer
	if err := SignTo(signer, data, SignerOptions{}, &buf); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if err := Verify(data, buf.Bytes(), other.PublicKey(), VerifyOptions{}); err == nil {
		t.Fatal("expected verification to fail for wrong public key")
	}
}
