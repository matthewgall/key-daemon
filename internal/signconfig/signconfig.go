// Package signconfig signs and verifies remote key-daemon configuration files
// using the OpenSSH SSHSIG detached signature format.
package signconfig

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultNamespace is the namespace used for key-daemon config signatures.
	DefaultNamespace = "key-daemon"
	// DefaultHash is the default hash algorithm for SSHSIG signatures.
	DefaultHash = "sha512"
)

// SignerOptions configure SignTo.
type SignerOptions struct {
	// Namespace is the SSHSIG namespace. It defaults to DefaultNamespace.
	Namespace string
	// HashAlg is the hash algorithm used for the signed message digest. It
	// defaults to DefaultHash.
	HashAlg string
}

// SignTo signs data with signer using the SSHSIG detached format and writes
// the armored signature to w. The public key included in the signature is
// taken from the signer.
func SignTo(signer ssh.Signer, data []byte, opts SignerOptions, w io.Writer) error {
	if opts.Namespace == "" {
		opts.Namespace = DefaultNamespace
	}
	if opts.HashAlg == "" {
		opts.HashAlg = DefaultHash
	}

	hashAlg := sshsig.HashAlgorithm(opts.HashAlg)
	if err := hashAlg.Supported(); err != nil {
		return err
	}

	sig, err := sshsig.Sign(bytes.NewReader(data), signer, hashAlg, opts.Namespace)
	if err != nil {
		return fmt.Errorf("sign config: %w", err)
	}

	if _, err := w.Write(sshsig.Armor(sig)); err != nil {
		return err
	}
	return nil
}

// VerifyOptions configure Verify.
type VerifyOptions struct {
	// Namespace constrains which namespace the signature must declare. An empty
	// value disables namespace checking.
	Namespace string
}

// Verify checks that sigBytes is a valid SSHSIG detached signature over data
// using publicKey. opts.Namespace may be used to require a specific namespace.
func Verify(data []byte, sigBytes []byte, publicKey ssh.PublicKey, opts VerifyOptions) error {
	s := strings.TrimSpace(string(sigBytes))
	var sig *sshsig.Signature
	var err error
	if strings.HasPrefix(s, "-----BEGIN SSH SIGNATURE-----") {
		sig, err = sshsig.Unarmor([]byte(s))
	} else {
		sig, err = sshsig.ParseSignature(sigBytes)
	}
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	ns := opts.Namespace
	if ns == "" {
		ns = sig.Namespace
	}

	hashAlg := sig.HashAlgorithm
	if err := hashAlg.Supported(); err != nil {
		return fmt.Errorf("unsupported signature hash algorithm %q: %w", hashAlg, err)
	}

	if err := sshsig.Verify(bytes.NewReader(data), sig, publicKey, hashAlg, ns); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}
