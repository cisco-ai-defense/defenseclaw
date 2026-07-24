// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"encoding/pem"
	"os"
	"testing"
)

func TestActionMapping(t *testing.T) {
	tests := []struct {
		action         string
		wantLifecycle  string
		wantActor      string
		wantEvent      string
		wantTransition string
	}{
		{"install-detected", "install", "watcher", "asset.discovered", "discover"},
		{"install-rejected", "block", "watcher", "", ""},
		{"install-allowed", "allow", "watcher", "", ""},
		{"install-allowed-skip-enforce", "allow", "watcher", "", ""},
		{"install-clean", "install", "watcher", "", ""},
		{"install-warning", "install", "watcher", "", ""},
		{"install-scan-error", "scan-error", "watcher", "", ""},
		{"install-enforced", "block", "watcher", "", ""},
		{"block", "block", "user", "", ""},
		{"watcher-block", "block", "watcher", "", ""},
		{"allow", "allow", "user", "", ""},
		{"quarantine", "quarantine", "defenseclaw", "", ""},
		{"restore", "restore", "user", "", ""},
		{"deploy", "install", "user", "", ""},
		{"stop", "uninstall", "user", "", ""},
		{"disable", "disable", "defenseclaw", "", ""},
		{"enable", "enable", "user", "", ""},
		{"api-skill-disable", "disable", "user", "", ""},
		{"api-skill-enable", "enable", "user", "", ""},
		{"api-plugin-disable", "disable", "user", "", ""},
		{"api-plugin-enable", "enable", "user", "", ""},
		{"watch-start", "watch-start", "watcher", "", ""},
		{"watch-stop", "watch-stop", "watcher", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			m, ok := actionMap[tt.action]
			if !ok {
				t.Fatalf("action %q not in actionMap", tt.action)
			}
			if m.LifecycleAction != tt.wantLifecycle {
				t.Errorf("lifecycle: got %s, want %s", m.LifecycleAction, tt.wantLifecycle)
			}
			if m.Actor != tt.wantActor {
				t.Errorf("actor: got %s, want %s", m.Actor, tt.wantActor)
			}
			public, found := AssetLifecycleAction(tt.action)
			if !found || public.CanonicalEvent != tt.wantEvent ||
				public.Transition != tt.wantTransition {
				t.Errorf("canonical mapping: got %+v found=%t", public, found)
			}
		})
	}
	if len(tests) != len(actionMap) {
		t.Fatalf("mapping test cases=%d actionMap=%d; add an explicit disposition for every action", len(tests), len(actionMap))
	}
}

func TestNonLifecycleActionsExcluded(t *testing.T) {
	nonLifecycle := []string{
		"sidecar-start", "sidecar-stop", "sidecar-connected",
		"gateway-tool-call", "gateway-tool-result",
		"gateway-approval-requested",
		"api-config-patch",
	}
	for _, action := range nonLifecycle {
		if _, ok := actionMap[action]; ok {
			t.Errorf("operational action %q should not be in lifecycle actionMap", action)
		}
	}
}

func TestDeviceFingerprint_MissingFile(t *testing.T) {
	fp := deviceFingerprint("/nonexistent/path/to/key")
	if fp != "" {
		t.Errorf("expected empty fingerprint for missing file, got %q", fp)
	}
}

func TestDeviceFingerprint_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.key"
	if err := os.WriteFile(path, []byte("not a PEM file"), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for invalid PEM, got %q", fp)
	}
}

func TestDeviceFingerprint_WrongSeedSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wrong.key"
	pemData := "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(pemData), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for wrong seed size, got %q", fp)
	}
}

func TestDeviceFingerprint_ValidKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device.key"

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: seed})
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatal(err)
	}

	fp := deviceFingerprint(path)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint for valid key")
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %s", len(fp), fp)
	}

	fp2 := deviceFingerprint(path)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %s != %s", fp, fp2)
	}
}
