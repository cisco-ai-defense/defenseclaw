// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxDeviceKeyBytes bounds the device key read. The on-disk key is a small PEM
// block; anything larger is a corrupt or hostile file, not an identity.
const maxDeviceKeyBytes = 64 << 10

// OSIdentity returns the OS-user join keys for the calling process.
//
// This must run in the hook process, which carries the real user's token. Never
// call it from the sidecar: a LocalSystem service would report the service
// account as the user, which the Identity Fabric projection forbids.
//
// On Windows it reports the process/thread token SID; elsewhere it reports the
// effective UID. Both come from the OS, never from agent-supplied hook JSON.
func OSIdentity() User {
	return osIdentity()
}

// HostOperatingSystem maps the build target to the Astrix enum.
func HostOperatingSystem() OperatingSystem {
	switch runtime.GOOS {
	case "windows":
		return OSWindows
	case "darwin":
		return OSMac
	case "linux":
		return OSLinux
	default:
		return ""
	}
}

// DeviceFingerprint derives DefenseClaw's stable device identifier from an
// existing device key, without ever creating one.
//
// The hook process must not mint device identity: key creation belongs to the
// gateway, and a hook that generated its own key would produce a second,
// competing device id. An absent key yields an empty string, which the caller
// reports as degraded rather than substituting a guess.
func DeviceFingerprint(deviceKeyFile string) (string, error) {
	path := strings.TrimSpace(deviceKeyFile)
	if path == "" {
		return "", errors.New("idfabric: device key path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	// A symlinked key is a redirection attempt, not an identity.
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("idfabric: device key path is a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("idfabric: device key path is not a regular file")
	}
	if info.Size() > maxDeviceKeyBytes {
		return "", errors.New("idfabric: device key file is implausibly large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("idfabric: device key is not PEM encoded")
	}
	pub, err := publicKeyFromPEMBlockBytes(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]), nil
}

// publicKeyFromPEMBlockBytes accepts either a raw Ed25519 seed or a full
// private key and returns the corresponding public key bytes.
func publicKeyFromPEMBlockBytes(raw []byte) (ed25519.PublicKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw).Public().(ed25519.PublicKey), nil
	default:
		return nil, errors.New("idfabric: unexpected device key length")
	}
}

// DefaultDeviceKeyFile is the conventional device key location under a
// DefenseClaw home directory.
func DefaultDeviceKeyFile(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	return filepath.Join(home, "device.key")
}
