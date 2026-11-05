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
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	return loadOrCreateIdentityAt(target, dataDir)
}

func loadOrCreateIdentityAt(target, dataDir string) (*DeviceIdentity, error) {
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
		narrowDeviceIdentityACL(target, dataDir)
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
	dataDir := ""
	var err error
	if len(dataDirs) == 1 {
		if !filepath.IsAbs(dataDirs[0]) {
			return "", "", fmt.Errorf("gateway: device identity data directory must be absolute")
		}
		dataDir, err = filepath.Abs(filepath.Clean(dataDirs[0]))
		if err != nil {
			return "", "", fmt.Errorf("gateway: normalize device identity data directory: %w", err)
		}
	}

	if !filepath.IsAbs(keyFile) {
		if len(dataDirs) != 1 {
			return "", "", fmt.Errorf("gateway: relative device key path requires an explicit absolute data directory")
		}
		resolved, ok := config.ResolveRelativeGatewayDeviceKeyFile(keyFile, dataDir)
		if !ok {
			return "", "", fmt.Errorf("gateway: relative device key path must stay strictly inside the data directory and use no volume")
		}
		return resolved, dataDir, nil
	}

	target, err := filepath.Abs(filepath.Clean(keyFile))
	if err != nil {
		return "", "", fmt.Errorf("gateway: normalize device key path: %w", err)
	}
	if dataDir == "" {
		dataDir = filepath.Dir(target)
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
			return fmt.Errorf(
				"gateway: device identity continuity artifact already exists: %s"+
					" (the device key is missing but its provenance files remain; restore the"+
					" key from a backup, or run: defenseclaw doctor --fix --fix-id"+
					" doctor.identity.device-key.initialize)",
				path,
			)
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
	return prepareFreshIdentityDirectoriesWith(
		dataDir,
		parent,
		safefile.ProtectDirectory,
		syncFreshIdentityDirectory,
	)
}

func prepareFreshIdentityDirectoriesWith(
	dataDir, parent string,
	protectDirectory func(string) error,
	syncDirectory func(string) error,
) error {
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
			if err := protectDirectory(next); err != nil {
				return fmt.Errorf("gateway: create private device key directory component %s: %w", next, err)
			}
		} else {
			return fmt.Errorf("gateway: inspect device key directory component %s: %w", next, inspectErr)
		}
		if err := validateFreshIdentityDirectory(next); err != nil {
			return err
		}
		// Persist, or re-assert after an interrupted prior attempt, each validated
		// directory name before a deeper component or identity artifact can be
		// created. Windows' helper is intentionally a no-op because directory
		// handles cannot be fsynced.
		if err := syncDirectory(current); err != nil {
			return fmt.Errorf("gateway: sync device key directory parent %s: %w", current, err)
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
	if handled, err := validateFreshIdentityManagedServiceDirectory(path); handled || err != nil {
		return err
	}
	if err := safefile.ValidatePrivateDirectory(path); err != nil {
		return fmt.Errorf("gateway: validate device identity directory %s: %w", path, err)
	}
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	if handled, err := writeFreshIdentityManagedServiceFile(path, data); handled || err != nil {
		return err
	}
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
	if err := syncFreshIdentityDirectory(filepath.Dir(path)); err != nil {
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

func normalizeMetadata(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}
