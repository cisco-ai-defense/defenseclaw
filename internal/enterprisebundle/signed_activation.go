// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Causes of an activation refusal (ActivationRefusal.Cause).
const (
	// ActivationNotStored: no stored version directory holds the bundle the
	// generation record names.
	ActivationNotStored = "not_confirmed"
	// ActivationSignature: the stored manifest is not signed by a key of
	// the installed trust anchors for this tenant and platform.
	ActivationSignature = "signature"
	// ActivationDigest: a file the bundle ships does not match files[].
	ActivationDigest = "digest"
	// ActivationConfig: the config.yaml the signed bundle renders is not
	// the installed config.yaml.
	ActivationConfig = "config"
)

// ActivationRefusal is why a config generation is not the content of a
// signed policy bundle stored on this device. It names the bundle the
// record named and never any file content.
type ActivationRefusal struct {
	Cause    string
	BundleID string
	Version  uint64
	Detail   string
}

func (e *ActivationRefusal) Error() string {
	return fmt.Sprintf("activation_not_signed (%s): bundle %s version %d: %s", e.Cause, e.BundleID, e.Version, e.Detail)
}

// SignatureCache remembers, in memory only, the manifests whose signature
// verified against one anchor file, so a reload checks each bundle once.
// The key binds the manifest bytes and the anchor bytes: a changed anchor
// file checks every manifest again. The zero value is ready.
type SignatureCache struct {
	mu sync.Mutex
	ok map[[2]string]bool
}

func (c *SignatureCache) verified(manifestSHA, anchorsSHA string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ok[[2]string{manifestSHA, anchorsSHA}]
}

func (c *SignatureCache) remember(manifestSHA, anchorsSHA string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok == nil {
		c.ok = map[[2]string]bool{}
	}
	if len(c.ok) >= 64 {
		clear(c.ok)
	}
	c.ok[[2]string{manifestSHA, anchorsSHA}] = true
}

// SignedVersion is a stored bundle version that passed CheckStoredVersion,
// with the config.yaml it renders against its own version directory (the
// bytes an apply installs).
type SignedVersion struct {
	Dir      string
	Manifest *Manifest
	KeyID    string
	Rendered []byte
}

// ActivationInput is what CheckSignedActivation and SignedVersions read.
type ActivationInput struct {
	// BundlesDir is the installed bundles directory (<etc>/bundles).
	BundlesDir string
	// Anchors are the installed trust anchors and AnchorsRaw their bytes.
	Anchors    *Anchors
	AnchorsRaw []byte
	// Platform is the platform the bundle must target.
	Platform string
	Cache    *SignatureCache
}

// CheckStoredVersion checks the stored version directory name as the
// gateway admits a bundle: the directory is a real directory named for the
// bundle, its manifest is signed by a trust anchor key that is not revoked
// (key validity dates were checked when the bundle was applied), for the
// anchors' tenant and this platform, and every file it ships matches
// files[]. Product-shipped policy packs are not in files[]; package
// integrity covers them.
func CheckStoredVersion(in ActivationInput, name string) (*SignedVersion, *ActivationRefusal) {
	refusal := func(cause, format string, args ...any) *ActivationRefusal {
		return &ActivationRefusal{Cause: cause, Detail: fmt.Sprintf(format, args...)}
	}
	if !IsVersionDirName(name) {
		return nil, refusal(ActivationNotStored, "%s is not a bundle version directory", safePath(name))
	}
	dir := filepath.Join(in.BundlesDir, name)
	b, err := ReadDir(dir)
	if err != nil {
		return nil, refusal(ActivationNotStored, "the stored bundle cannot be read: %s", boundedDetail(err.Error()))
	}
	m, err := DecodeManifest(b.Manifest)
	if err != nil {
		return nil, refusal(ActivationSignature, "the stored manifest is not valid: %s", boundedDetail(err.Error()))
	}
	if !validVersionDir(name, m.Version, m.BundleID) {
		return nil, refusal(ActivationNotStored, "the directory name does not match the stored manifest")
	}
	sig, err := DecodeSignature(b.Signature)
	if err != nil {
		return nil, refusal(ActivationSignature, "the stored signature is not valid")
	}
	if in.Anchors == nil {
		return nil, refusal(ActivationSignature, "no trust anchors")
	}
	key := in.Anchors.Key(sig.KeyID)
	if key == nil || key.Status == KeyRevoked {
		return nil, refusal(ActivationSignature, "key %s is not a trust anchor key that may sign", safePath(sig.KeyID))
	}
	manifestSum := sha256.Sum256(b.Manifest)
	anchorsSum := sha256.Sum256(in.AnchorsRaw)
	manifestSHA, anchorsSHA := hex.EncodeToString(manifestSum[:]), hex.EncodeToString(anchorsSum[:])
	if !in.Cache.verified(manifestSHA, anchorsSHA) {
		if err := VerifySignature(b.Manifest, sig, key.Public()); err != nil {
			return nil, refusal(ActivationSignature, "the manifest signature does not verify with key %s", safePath(sig.KeyID))
		}
		in.Cache.remember(manifestSHA, anchorsSHA)
	}
	if m.TenantID != in.Anchors.TenantID || !slices.Contains(m.Target.Platforms, in.Platform) {
		return nil, refusal(ActivationSignature, "the bundle is not for this tenant and platform")
	}
	if err := CheckFiles(m, b); err != nil {
		return nil, refusal(ActivationDigest, "%s", boundedDetail(err.Error()))
	}
	rendered, err := RenderConfig(b, dir)
	if err != nil {
		return nil, refusal(ActivationConfig, "the stored bundle config cannot be rendered: %s", boundedDetail(err.Error()))
	}
	return &SignedVersion{Dir: name, Manifest: m, KeyID: sig.KeyID, Rendered: rendered}, nil
}

// CheckSignedActivation admits raw, the installed config.yaml a generation
// record names as bundle bundleID at version (signed by signerKeyID when it
// names one), only when a version directory of that bundle in the store
// passes CheckStoredVersion and renders exactly raw. The store keeps the
// version directories of the in-flight, the confirmed and the last good
// bundle, so a new apply, an apply rollback and a repair of the confirmed
// bundle all pass; a record that names a bundle the store does not hold
// signed, or bytes no signed bundle renders, does not.
func CheckSignedActivation(in ActivationInput, bundleID string, version uint64, signerKeyID string, raw []byte) (*SignedVersion, *ActivationRefusal) {
	base := VersionDirName(version, bundleID)
	names := []string{}
	for _, name := range storedVersionDirNames(in.BundlesDir, VersionDirName(version, bundleID), VersionDirNameForReceipt(version, bundleID, bundleID)) {
		if validVersionDir(name, version, bundleID) {
			names = append(names, name)
		}
	}
	first := &ActivationRefusal{Cause: ActivationNotStored, Detail: "no stored version directory holds this bundle (" + safePath(base) + ")"}
	for _, name := range names {
		v, refusal := CheckStoredVersion(in, name)
		if refusal != nil {
			if first.Cause == ActivationNotStored {
				first = refusal
			}
			continue
		}
		if v.Manifest.BundleID != bundleID || v.Manifest.Version != version || (signerKeyID != "" && v.KeyID != signerKeyID) {
			continue
		}
		if bytes.Equal(v.Rendered, raw) {
			return v, nil
		}
		if first.Cause == ActivationNotStored {
			first = &ActivationRefusal{Cause: ActivationConfig, Detail: "the installed config.yaml is not the config this signed bundle renders"}
		}
	}
	first.BundleID, first.Version = bundleID, version
	return nil, first
}

// SignedVersions lists every stored version directory that passes
// CheckStoredVersion, highest bundle version first: the start fallback runs
// the newest signed bundle in memory when the installed config is not one.
func SignedVersions(in ActivationInput) []*SignedVersion {
	var out []*SignedVersion
	for _, name := range storedVersionDirNames(in.BundlesDir) {
		if v, refusal := CheckStoredVersion(in, name); refusal == nil {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Manifest.Version > out[j].Manifest.Version })
	return out
}

// maxPublicReceiptBytes bounds one public receipt the gateway reads to name
// a version directory.
const maxPublicReceiptBytes = 64 << 10

// storedVersionDirNames are the version directory names in bundlesDir. The
// store directory is 0711 on Linux and macOS (rel-1-0-6:GAP-0038): the
// gateway, which runs as the service account, can open a version directory
// (0750 root:service) by name but cannot list the store. When the listing is
// refused, the names are the extra names given (the first delivery of a
// bundle has its bundle id as receipt id) and the names the public receipt
// events and receipt.json give, each kept only when it is a directory. A name
// only says where to look: CheckStoredVersion still checks the signature and
// the files of what it finds.
func storedVersionDirNames(bundlesDir string, extra ...string) []string {
	if entries, err := os.ReadDir(bundlesDir); err == nil {
		names := []string{}
		for _, entry := range entries {
			if entry.IsDir() && IsVersionDirName(entry.Name()) {
				names = append(names, entry.Name())
			}
		}
		return names
	}
	seen := map[string]bool{}
	names := []string{}
	add := func(name string) {
		if seen[name] || !IsVersionDirName(name) {
			return
		}
		seen[name] = true
		if info, err := os.Lstat(filepath.Join(bundlesDir, name)); err == nil && info.IsDir() {
			names = append(names, name)
		}
	}
	for _, name := range extra {
		add(name)
	}
	fromReceipt := func(path string) {
		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, maxPublicReceiptBytes+1))
		if err != nil || len(raw) > maxPublicReceiptBytes {
			return
		}
		var r struct {
			ReceiptID string `json:"receipt_id"`
			BundleID  string `json:"bundle_id"`
			Version   uint64 `json:"version"`
		}
		if json.Unmarshal(raw, &r) != nil || !ValidBundleID(r.BundleID) || r.Version == 0 {
			return
		}
		add(VersionDirName(r.Version, r.BundleID))
		add(VersionDirNameForReceipt(r.Version, r.BundleID, r.BundleID))
		if receiptIDPattern.MatchString(r.ReceiptID) {
			add(VersionDirNameForReceipt(r.Version, r.BundleID, r.ReceiptID))
		}
	}
	fromReceipt(filepath.Join(bundlesDir, enterprisestatus.PublicReceiptName))
	events := filepath.Join(bundlesDir, enterprisestatus.PublicReceiptEventsDirName)
	if entries, err := os.ReadDir(events); err == nil {
		for i, entry := range entries {
			if i >= maxUnreportedReceiptEvents {
				break
			}
			if entry.Type().IsRegular() && filepath.Ext(entry.Name()) == ".json" {
				fromReceipt(filepath.Join(events, entry.Name()))
			}
		}
	}
	sort.Strings(names)
	return names
}
