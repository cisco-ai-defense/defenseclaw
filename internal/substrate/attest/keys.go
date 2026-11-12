// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Signer signs attestations with the cluster attestation key (ECDSA P-256).
// In a cluster the private key is a chart Secret mounted into the build
// job; no actor ever sees it.
type Signer struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// GenerateSigner makes a fresh P-256 key (tests, "setup" of a new cluster).
func GenerateSigner() (*Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return newSigner(k)
}

func newSigner(k *ecdsa.PrivateKey) (*Signer, error) {
	if k.Curve != elliptic.P256() {
		return nil, errors.New("attestation key must be ECDSA P-256")
	}
	id, err := keyIDOf(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: k, keyID: id}, nil
}

// ParseSigner reads a PEM private key (PKCS#8 "PRIVATE KEY" or SEC1
// "EC PRIVATE KEY"). cosign's encrypted key format is not read: export the
// key unencrypted into the cluster Secret.
func ParseSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("attestation key: no PEM block")
	}
	var k *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestation key: %w", err)
		}
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("attestation key: not an ECDSA key")
		}
		k = ec
	case "EC PRIVATE KEY":
		ec, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestation key: %w", err)
		}
		k = ec
	default:
		return nil, fmt.Errorf("attestation key: PEM type %q is not supported", block.Type)
	}
	return newSigner(k)
}

// LoadSigner reads a signer from a file. The file must not be readable by
// group or others.
func LoadSigner(path string) (*Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("attestation key %s is readable by group or others (mode %o)", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSigner(data)
}

// KeyID is the hex SHA-256 of the DER public key.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKeyPEM is the PKIX PEM of the public key (cosign.pub format).
func (s *Signer) PublicKeyPEM() ([]byte, error) { return publicPEM(&s.key.PublicKey) }

// PrivateKeyPEM is the PKCS#8 PEM, for storing in a Secret.
func (s *Signer) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func (s *Signer) sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func publicPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func keyIDOf(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// Anchor is one trusted public key.
type Anchor struct {
	Public *ecdsa.PublicKey
	KeyID  string
	// Name is a label for events ("cluster-2026-11"), never trusted input.
	Name string
	// NotBefore and NotAfter bound the key's use; zero means unbounded.
	NotBefore time.Time
	NotAfter  time.Time
}

var (
	errAnchorNotYetValid = errors.New("trust anchor is not valid yet")
	errAnchorExpired     = errors.New("trust anchor has expired")
	errAnchorRevoked     = errors.New("trust anchor is revoked")
)

func (a *Anchor) usable(now time.Time) error {
	if !a.NotBefore.IsZero() && now.Before(a.NotBefore) {
		return errAnchorNotYetValid
	}
	if !a.NotAfter.IsZero() && now.After(a.NotAfter) {
		return errAnchorExpired
	}
	return nil
}

// TrustAnchors is the set of public keys whose signatures the controller
// accepts: the cluster attestation key, plus the previous key during a
// rotation. A revoked key id is refused even if its key is still listed.
type TrustAnchors struct {
	anchors []*Anchor
	revoked map[string]bool
}

// NewTrustAnchors returns an empty set.
func NewTrustAnchors() *TrustAnchors { return &TrustAnchors{revoked: map[string]bool{}} }

// Add trusts a public key.
func (t *TrustAnchors) Add(a *Anchor) error {
	if a == nil || a.Public == nil || a.Public.Curve != elliptic.P256() {
		return errors.New("trust anchor must be an ECDSA P-256 public key")
	}
	id, err := keyIDOf(a.Public)
	if err != nil {
		return err
	}
	a.KeyID = id
	for _, have := range t.anchors {
		if have.KeyID == id {
			return nil
		}
	}
	t.anchors = append(t.anchors, a)
	return nil
}

// AddSigner trusts a signer's own public key (tests, single-key clusters).
func (t *TrustAnchors) AddSigner(s *Signer, name string) error {
	return t.Add(&Anchor{Public: &s.key.PublicKey, Name: name})
}

// Revoke refuses a key id from now on.
func (t *TrustAnchors) Revoke(keyID string) { t.revoked[strings.ToLower(keyID)] = true }

// Len is the number of trusted keys.
func (t *TrustAnchors) Len() int { return len(t.anchors) }

// KeyIDs lists the trusted key ids, sorted.
func (t *TrustAnchors) KeyIDs() []string {
	ids := make([]string, 0, len(t.anchors))
	for _, a := range t.anchors {
		ids = append(ids, a.KeyID)
	}
	sort.Strings(ids)
	return ids
}

// candidates returns the anchors to try for a signature: the one the key id
// names first, then the rest.
func (t *TrustAnchors) candidates(hint string) []*Anchor {
	var first, rest []*Anchor
	for _, a := range t.anchors {
		if hint != "" && a.KeyID == hint {
			first = append(first, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(first, rest...)
}

// IsRevoked reports whether a key id is revoked.
func (t *TrustAnchors) IsRevoked(keyID string) bool { return t.revoked[strings.ToLower(keyID)] }

// ParseAnchors reads a PEM bundle of PUBLIC KEY blocks. Optional PEM headers
// Name, Not-Before and Not-After (RFC 3339) bound a key. A block of any
// other type is an error, so a private key pasted into the trust file is
// never silently ignored.
func ParseAnchors(bundle []byte) (*TrustAnchors, error) {
	t := NewTrustAnchors()
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("trust anchors: PEM type %q is not a PUBLIC KEY", block.Type)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust anchors: %w", err)
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("trust anchors: not an ECDSA key")
		}
		a := &Anchor{Public: pub, Name: block.Headers["Name"]}
		if v := block.Headers["Not-Before"]; v != "" {
			if a.NotBefore, err = time.Parse(time.RFC3339, v); err != nil {
				return nil, fmt.Errorf("trust anchors: Not-Before: %w", err)
			}
		}
		if v := block.Headers["Not-After"]; v != "" {
			if a.NotAfter, err = time.Parse(time.RFC3339, v); err != nil {
				return nil, fmt.Errorf("trust anchors: Not-After: %w", err)
			}
		}
		if err := t.Add(a); err != nil {
			return nil, err
		}
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("trust anchors: trailing data after the last PEM block")
	}
	if t.Len() == 0 {
		return nil, errors.New("trust anchors: no keys")
	}
	return t, nil
}

// LoadAnchors reads a trust bundle file.
func LoadAnchors(path string) (*TrustAnchors, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAnchors(data)
}

func (t *TrustAnchors) has(keyID string) bool {
	for _, a := range t.anchors {
		if a.KeyID == keyID {
			return true
		}
	}
	return false
}
