// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// ConfirmedProductFloor is the min_product_version of the confirmed bundle:
// the lowest DefenseClaw release the device may run while that bundle
// enforces. It is "" when no bundle is confirmed or the bundle sets none. A
// confirmed manifest whose bytes no longer match the recorded hash is an
// error. Other bundle files are checked when they are applied.
func (s *Store) ConfirmedProductFloor() (string, error) {
	// Recovery may need to replace a damaged file from the committed config.
	// The release floor lives in the manifest, whose exact bytes are pinned by
	// the confirmed state. Reading all files here would prevent that recovery.
	m, err := s.ConfirmedManifest()
	if err != nil || m == nil {
		return "", err
	}
	return m.MinProductVersion, nil
}

// ConfirmedManifest is the manifest of the confirmed bundle, nil when no
// bundle is confirmed. A stored manifest whose bytes no longer match the
// recorded hash is an error.
func (s *Store) ConfirmedManifest() (*Manifest, error) {
	st, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	if st.Current == nil {
		return nil, nil
	}
	return s.confirmedManifest(st.Current)
}

func (s *Store) confirmedManifest(ref *Ref) (*Manifest, error) {
	if err := ref.validate(); err != nil {
		return nil, &Error{Code: CodeStateInvalid, Path: StateFileName, Detail: err.Error()}
	}
	dir := s.VersionDir(ref.Dir)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() {
		return nil, refuse(CodeArchiveInvalid, ManifestName, "confirmed bundle directory is unavailable")
	}
	path := filepath.Join(dir, ManifestName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, refuse(CodeArchiveInvalid, ManifestName, "confirmed manifest is unavailable")
	}
	raw, readErr := newCollector().readFile(path, ManifestName, info)
	if readErr != nil {
		return nil, readErr
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != ref.ManifestSHA256 {
		return nil, refuse(CodeFileHashMismatch, ManifestName, "the stored manifest of bundle %s version %d is not the confirmed one", ref.BundleID, ref.Version)
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		return nil, err
	}
	if m.BundleID != ref.BundleID || m.Version != ref.Version {
		return nil, refuse(CodeStateInvalid, ManifestName, "confirmed manifest does not match the bundle state")
	}
	return m, nil
}
