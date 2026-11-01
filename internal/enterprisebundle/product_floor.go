// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WarnProductBelowFloor is the status and verify warning of a build that
// runs below the release floor (min_product_version) of the confirmed
// bundle. It is a warning only: it starts no repair, reinstall or hook
// fail-mode change.
const WarnProductBelowFloor = "product_below_floor"

// ReleaseFloorRefusal explains why DefenseClaw version may not be
// installed while a confirmed bundle requires floor, nil when it may (or
// floor is ""). It places the version as the bundle verifier does
// (CheckProductVersion): a version that is not a release (dev, 1.0.4.1,
// 1.0.x) never meets a floor. The caller adds its refusal code.
func ReleaseFloorRefusal(version, floor string) error {
	if floor == "" {
		return nil
	}
	candidate := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !IsReleaseVersion(candidate) {
		if len(candidate) > 64 {
			candidate = candidate[:64] + "..."
		}
		return fmt.Errorf("the signed policy bundle needs DefenseClaw %s or later, and %q is not a release version, so it cannot meet that floor; install a release at or above %s, or deliver a bundle signed without --min-product-version first", floor, candidate, floor)
	}
	if CheckProductVersion(floor, candidate) != nil {
		return fmt.Errorf("the signed policy bundle needs DefenseClaw %s or later, and this is %s; to go back, deliver a bundle signed with a lower --min-product-version first", floor, candidate)
	}
	return nil
}

// ProductBelowFloorWarning is the product_below_floor warning for running
// version under the confirmed bundle of s, nil when the build meets the
// floor, no floor is set or the floor cannot be read (other checks report
// an unreadable store). A build that is not a release (a development build)
// is not warned.
func (s *Store) ProductBelowFloorWarning(version string) *Warning {
	floor, err := s.ConfirmedProductFloor()
	if err != nil || floor == "" {
		return nil
	}
	running := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !IsReleaseVersion(running) || CheckProductVersion(floor, running) == nil {
		return nil
	}
	return &Warning{Code: WarnProductBelowFloor, Message: fmt.Sprintf(
		"this DefenseClaw %s is below the release the confirmed policy bundle requires (%s); policy keeps enforcing, but install %s or later, or deliver a bundle signed with a lower --min-product-version",
		running, floor, floor)}
}

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
