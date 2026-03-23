package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DeviceIdentity holds the Ed25519 keypair for gateway device authentication.
type DeviceIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	DeviceID   string
}

// LoadOrCreateIdentity loads an existing device keypair from disk or generates
// a new one. The keypair is stored as a PEM-encoded Ed25519 private key.
func LoadOrCreateIdentity(keyFile string) (*DeviceIdentity, error) {
	if data, err := os.ReadFile(keyFile); err == nil {
		return parseIdentity(data)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate device key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return nil, fmt.Errorf("gateway: create key dir: %w", err)
	}

	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	}
	pemData := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyFile, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("gateway: write device key: %w", err)
	}

	return &DeviceIdentity{
		PrivateKey: priv,
		PublicKey:  pub,
		DeviceID:   fingerprint(pub),
	}, nil
}

func parseIdentity(data []byte) (*DeviceIdentity, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("gateway: invalid PEM in device key file")
	}

	seed := block.Bytes
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("gateway: invalid seed length %d (expected %d)", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return &DeviceIdentity{
		PrivateKey: priv,
		PublicKey:  pub,
		DeviceID:   fingerprint(pub),
	}, nil
}

func fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// ConnectDeviceParams carries the per-connection fields needed to build the
// v3 challenge-response payload that the OpenClaw gateway verifies.
type ConnectDeviceParams struct {
	ClientID     string
	ClientMode   string
	Role         string
	Scopes       []string
	Token        string
	Nonce        string
	Platform     string
	DeviceFamily string
}

// SignChallenge signs the v3 device auth payload and returns a base64url signature.
func (d *DeviceIdentity) SignChallenge(p ConnectDeviceParams, signedAtMs int64) string {
	scopeStr := strings.Join(p.Scopes, ",")
	token := p.Token
	payload := strings.Join([]string{
		"v3",
		d.DeviceID,
		p.ClientID,
		p.ClientMode,
		p.Role,
		scopeStr,
		fmt.Sprintf("%d", signedAtMs),
		token,
		p.Nonce,
		normalizeMetadata(p.Platform),
		normalizeMetadata(p.DeviceFamily),
	}, "|")
	sig := ed25519.Sign(d.PrivateKey, []byte(payload))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// PublicKeyBase64URL returns the base64url-encoded raw public key.
func (d *DeviceIdentity) PublicKeyBase64URL() string {
	return base64.RawURLEncoding.EncodeToString(d.PublicKey)
}

// ConnectDevice builds the device identity block for the connect params.
func (d *DeviceIdentity) ConnectDevice(p ConnectDeviceParams) map[string]interface{} {
	signedAt := time.Now().UnixMilli()
	return map[string]interface{}{
		"id":        d.DeviceID,
		"publicKey": d.PublicKeyBase64URL(),
		"signature": d.SignChallenge(p, signedAt),
		"signedAt":  signedAt,
		"nonce":     p.Nonce,
	}
}

func normalizeMetadata(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}
