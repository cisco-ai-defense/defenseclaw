//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// g582 round 4 (class audit E2): on standalone a correlation key another
// account owns is never adopted in place (that account knows, or chose, the
// material); it is rotated. Secure Client keeps the owner repair
// (TestWindowsCorrelationKeyUntrustedOwnerIsRepairedOrRotated).
func TestWindowsCorrelationKeyUntrustedOwnerIsRotatedNotAdoptedOnStandalone(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("resolve current Windows user: %v", err)
	}
	foreign, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	expected := current.User.Sid
	pinWindowsCorrelationExpectedOwner(t, &expected)
	previous := windowsCorrelationStandaloneRotates
	windowsCorrelationStandaloneRotates = func() bool { return true }
	t.Cleanup(func() { windowsCorrelationStandaloneRotates = previous })

	dir := t.TempDir()
	original, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected = foreign // the key's owner (the test user) is not the gateway's
	path := filepath.Join(dir, correlationKeyFilename)
	repairs := 0
	var rotated string
	realRotate := windowsCorrelationKeyRotate
	stubWindowsCorrelationOwnerRecovery(t,
		func(string, windows.Handle) error {
			repairs++
			return nil
		},
		func(target string, identity windows.ByHandleFileInformation) error {
			rotated = target
			if err := realRotate(target, identity); err != nil {
				t.Skipf("key rotation needs administrator rights here: %v", err)
			}
			expected = current.User.Sid
			return nil
		},
	)
	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load after rotation: %v", err)
	}
	if repairs != 0 {
		t.Fatalf("the untrusted owner was adopted in place (%d owner repairs)", repairs)
	}
	if rotated != path || loaded.ID() == original.ID() {
		t.Fatalf("rotated %q (want %q), same key %t: an untrusted-owned key stayed in use", rotated, path, loaded.ID() == original.ID())
	}
}
