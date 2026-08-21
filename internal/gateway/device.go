// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	deviceProvenanceSecretName = "device.provenance.secret"
	deviceProvenancePrefix     = "defenseclaw-device-provenance-v1:"
)

// DeviceIdentity holds the Ed25519 keypair for gateway device authentication.
type DeviceIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	DeviceID   string
}

// LoadOrCreateIdentity loads an existing device keypair from disk or generates
// a new one. The keypair is stored as a PEM-encoded Ed25519 private key.
func LoadOrCreateIdentity(keyFile string, dataDirs ...string) (*DeviceIdentity, error) {
	if len(dataDirs) > 1 {
		return nil, fmt.Errorf("gateway: device identity accepts at most one data directory")
	}
	target, dataDir, err := normalizeDeviceIdentityPaths(keyFile, dataDirs)
	if err != nil {
		return nil, err
	}
	if err := validateDeviceIdentityPathSyntax(target, dataDir); err != nil {
		return nil, err
	}
	if err := validateDeviceIdentityArtifactLayout(target, dataDir); err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(target); err == nil {
		// Existing identities may pre-date the HMAC provenance contract. Never
		// mint provenance for one here: doing so would bless a key that this
		// process did not create. Doctor reports that state as legacy until an
		// operator performs an explicit continuity-aware recovery.
		return parseIdentity(data)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("gateway: read device key: %w", err)
	}

	if err := validateFreshDeviceIdentityLocation(target, dataDir); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate device key: %w", err)
	}

	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	}
	pemData := pem.EncodeToMemory(block)
	if err := writeFreshDeviceIdentity(target, dataDir, pemData); err != nil {
		return nil, err
	}

	return &DeviceIdentity{
		PrivateKey: priv,
		PublicKey:  pub,
		DeviceID:   fingerprint(pub),
	}, nil
}

func normalizeDeviceIdentityPaths(keyFile string, dataDirs []string) (string, string, error) {
	if !filepath.IsAbs(keyFile) {
		return "", "", fmt.Errorf("gateway: device key path must be absolute")
	}
	target, err := filepath.Abs(filepath.Clean(keyFile))
	if err != nil {
		return "", "", fmt.Errorf("gateway: normalize device key path: %w", err)
	}

	dataDir := filepath.Dir(target)
	if len(dataDirs) == 1 {
		if !filepath.IsAbs(dataDirs[0]) {
			return "", "", fmt.Errorf("gateway: device identity data directory must be absolute")
		}
		dataDir, err = filepath.Abs(filepath.Clean(dataDirs[0]))
		if err != nil {
			return "", "", fmt.Errorf("gateway: normalize device identity data directory: %w", err)
		}
	}
	return target, dataDir, nil
}

func validateFreshDeviceIdentityLocation(target, dataDir string) error {
	relative, err := filepath.Rel(dataDir, target)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("gateway: missing device key must be strictly inside the data directory")
	}
	return nil
}

func validateDeviceIdentityArtifactLayout(target, dataDir string) error {
	if filepath.Dir(dataDir) == dataDir {
		return fmt.Errorf("gateway: device identity data directory cannot be a filesystem root")
	}
	secretPath := filepath.Join(dataDir, deviceProvenanceSecretName)
	provenancePath := target + ".provenance"
	artifacts := []string{target, secretPath, provenancePath}
	for left := 0; left < len(artifacts); left++ {
		for right := left + 1; right < len(artifacts); right++ {
			if deviceIdentityPathEqual(artifacts[left], artifacts[right]) {
				return fmt.Errorf("gateway: device identity artifact paths must be distinct")
			}
		}
	}
	if deviceIdentityPathWithin(target, secretPath) {
		return fmt.Errorf("gateway: device key path cannot use the reserved provenance secret path")
	}
	return nil
}

func deviceIdentityPathEqual(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return strings.EqualFold(left, right)
}

func deviceIdentityPathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if strings.EqualFold(path, root) {
		return true
	}
	return len(path) > len(root) && path[len(root)] == os.PathSeparator &&
		strings.EqualFold(path[:len(root)], root)
}

// writeFreshDeviceIdentity publishes the provenance secret and HMAC before the
// key name becomes visible. All writes are CREATE_NEW and private, so a crash
// or race leaves continuity evidence that blocks an unsafe retry instead of
// overwriting or blessing an identity created by another process.
func writeFreshDeviceIdentity(keyFile, dataDir string, keyData []byte) error {
	parent := filepath.Dir(keyFile)
	if err := prepareFreshIdentityDirectories(dataDir, parent); err != nil {
		return err
	}

	secretPath := filepath.Join(dataDir, deviceProvenanceSecretName)
	provenancePath := keyFile + ".provenance"
	if err := validateFreshIdentityDirectories(dataDir, parent); err != nil {
		return err
	}
	for _, path := range []string{keyFile, secretPath, provenancePath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("gateway: device identity continuity artifact already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("gateway: inspect device identity continuity artifact %s: %w", path, err)
		}
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("gateway: generate device provenance secret: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(keyData); err != nil {
		return fmt.Errorf("gateway: hash device key provenance: %w", err)
	}
	provenance := []byte(deviceProvenancePrefix + hex.EncodeToString(mac.Sum(nil)) + "\n")

	for _, artifact := range []struct {
		path string
		data []byte
	}{
		{path: secretPath, data: secret},
		{path: provenancePath, data: provenance},
		{path: keyFile, data: keyData},
	} {
		if err := validateFreshIdentityDirectories(dataDir, parent); err != nil {
			return err
		}
		if err := writeNewPrivateFile(artifact.path, artifact.data); err != nil {
			return fmt.Errorf("gateway: publish device identity artifact %s: %w", artifact.path, err)
		}
	}
	return nil
}

func prepareFreshIdentityDirectories(dataDir, parent string) error {
	if err := validateFreshIdentityDirectory(dataDir); err != nil {
		return fmt.Errorf("gateway: device identity data directory must already be private: %w", err)
	}
	relative, err := filepath.Rel(dataDir, parent)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("gateway: device key parent must stay inside the data directory")
	}
	if relative == "." {
		return nil
	}

	current := dataDir
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("gateway: invalid device key directory component")
		}
		if err := validateFreshIdentityDirectory(current); err != nil {
			return err
		}
		next := filepath.Join(current, component)
		info, inspectErr := os.Lstat(next)
		if inspectErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("gateway: device key directory component is indirect or not a directory: %s", next)
			}
		} else if os.IsNotExist(inspectErr) {
			// next is exactly one child beneath the already validated private
			// current directory. Let the platform helper create it privately in
			// the first place; on Windows this avoids a brief inherited-DACL
			// window before protection is applied.
			if err := safefile.ProtectDirectory(next); err != nil {
				return fmt.Errorf("gateway: create private device key directory component %s: %w", next, err)
			}
		} else {
			return fmt.Errorf("gateway: inspect device key directory component %s: %w", next, inspectErr)
		}
		if err := validateFreshIdentityDirectory(next); err != nil {
			return err
		}
		current = next
	}
	return nil
}

func validateFreshIdentityDirectories(dataDir, parent string) error {
	relative, err := filepath.Rel(dataDir, parent)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("gateway: device key parent must stay inside the data directory")
	}
	current := dataDir
	if err := validateFreshIdentityDirectory(current); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		if err := validateFreshIdentityDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func validateFreshIdentityDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("gateway: inspect device identity directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("gateway: device identity directory is indirect or not a directory: %s", path)
	}
	if err := validateFreshIdentityDirectoryPlatform(path, info); err != nil {
		return err
	}
	if err := safefile.ValidatePrivateDirectory(path); err != nil {
		return fmt.Errorf("gateway: validate device identity directory %s: %w", path, err)
	}
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	file, err := safefile.CreateExclusive(path)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return err
	}
	return validateFreshIdentityFilePlatform(path)
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

// RepairPairing writes (or overwrites) the sidecar's device entry into
// OpenClaw's devices/paired.json so the gateway can authenticate on the
// next connect attempt.  This is called automatically when a connect
// handshake fails with "token_missing" or "unauthorized", which happens
// when openclaw regenerates its pairing state (e.g. after a restart).
//
// S3.HIGH_BUG ("RepairPairing can erase unrelated paired
// devices"): the previous implementation silently swallowed JSON parse
// errors on paired.json. A truncated or partially-written file would
// be treated as an empty map and the subsequent rewrite would erase
// every other paired device. The hardened version:
//
//  1. Fails closed on parse errors -- the caller MUST surface the
//     failure rather than silently corrupting OpenClaw's pairing
//     database. A snapshot of the unparseable file is kept beside the
//     original as paired.json.corrupt.<unix-nanos> for forensics so
//     the operator can recover the original byte stream.
//  2. Writes via a same-directory temp file, fsync, chmod 0600, then
//     os.Rename for atomicity. A crash between truncate and write can
//     no longer leave OpenClaw's pairing database half-empty.
//  3. Tightens the on-disk perms from 0o644 to 0o600 so the device
//     identity / token references are not world-readable.
func (d *DeviceIdentity) RepairPairing(sandboxHome string) error {
	devicesDir := filepath.Join(sandboxHome, ".openclaw", "devices")
	pairedPath := filepath.Join(devicesDir, "paired.json")

	paired := make(map[string]interface{})
	existingData, readErr := os.ReadFile(pairedPath)
	if readErr == nil && len(existingData) > 0 {
		if unmarshalErr := json.Unmarshal(existingData, &paired); unmarshalErr != nil {
			// Snapshot the corrupt file so the operator can recover
			// or post-mortem the bytes; never overwrite blindly.
			backup := fmt.Sprintf("%s.corrupt.%d", pairedPath, time.Now().UnixNano())
			if backupErr := safefile.WritePrivate(backup, existingData); backupErr != nil {
				fmt.Fprintf(os.Stderr,
					"[gateway] repair pairing: failed to back up corrupt paired.json (%v); refusing to overwrite\n",
					backupErr)
			} else {
				fmt.Fprintf(os.Stderr,
					"[gateway] repair pairing: corrupt paired.json snapshotted to %s; refusing to overwrite\n",
					backup)
			}
			return fmt.Errorf("gateway: repair pairing: paired.json is unparseable: %w", unmarshalErr)
		}
	} else if readErr != nil && !os.IsNotExist(readErr) {
		// Read errors other than file-not-found are fatal -- a
		// permission or I/O failure must not be silently ignored.
		return fmt.Errorf("gateway: repair pairing: read existing paired.json: %w", readErr)
	}

	nowMs := time.Now().UnixMilli()
	scopes := []string{
		"operator.read", "operator.write",
		"operator.admin", "operator.approvals",
	}

	existing, _ := paired[d.DeviceID].(map[string]interface{})
	if existing == nil {
		existing = map[string]interface{}{}
	}

	tokens := existing["tokens"]
	if tokens == nil {
		tokens = map[string]interface{}{}
	}
	createdAt := existing["createdAtMs"]
	if createdAt == nil {
		createdAt = nowMs
	}

	// Platform must match what the connect handshake reports
	// (client.go uses runtime.GOOS); otherwise OpenClaw flags this as
	// `metadata-upgrade` ("device identity changed and must be re-approved")
	// on every reconnect and the gateway link gets stuck in NOT_PAIRED.
	// See gateway-rooted regression: hardcoding "linux" here while
	// connecting from darwin produced an infinite RECONNECTING loop
	// even with a valid paired.json entry.
	paired[d.DeviceID] = map[string]interface{}{
		"deviceId":       d.DeviceID,
		"publicKey":      d.PublicKeyBase64URL(),
		"displayName":    "defenseclaw-sidecar",
		"platform":       runtime.GOOS,
		"deviceFamily":   existing["deviceFamily"],
		"clientId":       "gateway-client",
		"clientMode":     "backend",
		"role":           "operator",
		"roles":          []string{"operator"},
		"scopes":         scopes,
		"approvedScopes": scopes,
		"tokens":         tokens,
		"createdAtMs":    createdAt,
		"approvedAtMs":   nowMs,
	}

	if err := os.MkdirAll(devicesDir, 0o755); err != nil {
		return fmt.Errorf("gateway: repair pairing: mkdir: %w", err)
	}

	data, err := json.MarshalIndent(paired, "", "  ")
	if err != nil {
		return fmt.Errorf("gateway: repair pairing: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := atomicWritePairedJSON(pairedPath, data); err != nil {
		return fmt.Errorf("gateway: repair pairing: write: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[gateway] repaired device pairing in %s\n", pairedPath)
	return nil
}

// atomicWritePairedJSON writes data to path through a same-directory
// temp file, fsyncs the contents, chmods to 0600, and renames over the
// destination. A crash anywhere before os.Rename leaves the original
// file intact; a crash after rename leaves the new content intact.
// The temp file is created with O_EXCL so a stale tmp from a prior
// crash does not silently get reused.
func atomicWritePairedJSON(path string, data []byte) error {
	return safefile.WritePrivate(path, data)
}

func normalizeMetadata(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}
