// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"runtime"
	"strings"
	"testing"
)

// TestEffectivePeerAuthKindGating pins the spec 004 REQ-11 table:
//
//   - ManagedIPCEnabled() == false ⇒ "" regardless of runtime.GOOS.
//     (No IPC server, no peer-auth surface.)
//   - Managed_enterprise on every OS ⇒ "UnixPeer".
//
// Non-managed cases below produce "" on every OS. See
// TestEffectivePeerAuthKindManagedEnterprise for the managed-mode
// assertion on the current CI OS (CR spec-004:PRRT_kwDORuAK-s6ankzW).
func TestEffectivePeerAuthKindGating(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "non-managed deployment (unmanaged_byod)",
			cfg:  &Config{DeploymentMode: string(DeploymentModeUnmanagedBYOD)},
			want: "",
		},
		{
			name: "ci_cd — no IPC surface",
			cfg:  &Config{DeploymentMode: string(DeploymentModeCICD)},
			want: "",
		},
		{
			name: "sandboxed — no IPC surface",
			cfg:  &Config{DeploymentMode: string(DeploymentModeSandboxed)},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.EffectivePeerAuthKind(); got != tc.want {
				t.Fatalf("EffectivePeerAuthKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectivePeerAuthKindManagedEnterprise is the release-time
// assertion the GA gate in internal/ipc/authposture_gagate.go relies
// on: managed_enterprise reports an authenticated peer kind on every
// OS, Windows included. The Windows runner used to see
// "UnixPeerUnauthenticated"; that kind no longer exists.
func TestEffectivePeerAuthKindManagedEnterprise(t *testing.T) {
	cfg := &Config{DeploymentMode: string(DeploymentModeManagedEnterprise)}
	got := cfg.EffectivePeerAuthKind()
	if got != peerAuthKindUnixPeer {
		t.Fatalf("managed_enterprise on %s: EffectivePeerAuthKind() = %q, want %q",
			runtime.GOOS, got, peerAuthKindUnixPeer)
	}
	if strings.Contains(strings.ToLower(got), "unauthenticated") {
		t.Fatalf("managed_enterprise on %s reports an unauthenticated peer kind %q", runtime.GOOS, got)
	}
}

func TestDefaultSecureClientPolicyCarriesWindowsIdentity(t *testing.T) {
	def := DefaultSecureClientPolicy()
	if len(def.AllowedWindowsSigners) != 1 || def.AllowedWindowsSigners[0] != "Cisco Systems, Inc." {
		t.Fatalf("AllowedWindowsSigners = %q", def.AllowedWindowsSigners)
	}
	if len(def.AllowedWindowsImages) != 1 || def.AllowedWindowsImages[0] != `UI\csc_ui.exe` {
		t.Fatalf("AllowedWindowsImages = %q", def.AllowedWindowsImages)
	}
	for _, signer := range def.AllowedWindowsSigners {
		if err := ValidateWindowsSecureClientSigner(signer); err != nil {
			t.Fatalf("default signer %q rejected: %v", signer, err)
		}
	}
	for _, image := range def.AllowedWindowsImages {
		if err := ValidateWindowsSecureClientImage(image); err != nil {
			t.Fatalf("default image %q rejected: %v", image, err)
		}
	}
}

func TestValidateWindowsSecureClientImage(t *testing.T) {
	valid := []string{
		`UI\csc_ui.exe`,
		`csc_ui.exe`,
		`UI\CSC_UI.EXE`,
		`Sub Dir\Tool (x64)\gui.exe`,
	}
	for _, image := range valid {
		if err := ValidateWindowsSecureClientImage(image); err != nil {
			t.Errorf("ValidateWindowsSecureClientImage(%q) = %v, want nil", image, err)
		}
	}
	invalid := map[string]string{
		"empty":                "",
		"padded":               ` UI\csc_ui.exe`,
		"absolute drive":       `C:\Users\Public\csc_ui.exe`,
		"drive relative":       `C:csc_ui.exe`,
		"rooted":               `\Users\Public\csc_ui.exe`,
		"unc":                  `\\server\share\csc_ui.exe`,
		"forward slash":        `UI/csc_ui.exe`,
		"parent traversal":     `..\..\..\Users\Public\csc_ui.exe`,
		"inner traversal":      `UI\..\csc_ui.exe`,
		"dot segment":          `.\csc_ui.exe`,
		"empty segment":        `UI\\csc_ui.exe`,
		"alternate data":       `UI\csc_ui.exe:stream`,
		"wildcard":             `UI\*.exe`,
		"trailing dot":         `UI\csc_ui.exe.`,
		"trailing space dir":   `UI \csc_ui.exe`,
		"not an exe":           `UI\csc_ui.dll`,
		"bare extension":       `.exe`,
		"device name":          `NUL\csc_ui.exe`,
		"device name with ext": `UI\com1.exe`,
		"control character":    "UI\\csc\x00ui.exe",
		"too long":             strings.Repeat("a", 260) + ".exe",
	}
	for name, image := range invalid {
		if err := ValidateWindowsSecureClientImage(image); err == nil {
			t.Errorf("%s: ValidateWindowsSecureClientImage(%q) = nil, want error", name, image)
		}
	}
}

func TestValidateWindowsSecureClientSigner(t *testing.T) {
	if err := ValidateWindowsSecureClientSigner("Cisco Systems, Inc."); err != nil {
		t.Fatalf("default signer rejected: %v", err)
	}
	for _, signer := range []string{"", " Cisco Systems, Inc.", "Cisco\nSystems", strings.Repeat("a", 257)} {
		if err := ValidateWindowsSecureClientSigner(signer); err == nil {
			t.Errorf("ValidateWindowsSecureClientSigner(%q) = nil, want error", signer)
		}
	}
}

// TestValidateManagedIPCPeerAuthKnobsByPlatform drives both platform
// branches on every build host.
func TestValidateManagedIPCPeerAuthKnobsByPlatform(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		mode    string
		mutate  func(*ManagedIPCConfig)
		wantErr string
	}{
		{name: "windows defaults", goos: "windows", mode: "managed_enterprise", mutate: func(*ManagedIPCConfig) {}},
		{name: "windows override accepted", goos: "windows", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsSigners = []string{"Cisco Systems, Inc."}
			m.AllowedWindowsImages = []string{`UI\csc_ui.exe`, `UI\csc_ui_next.exe`}
		}},
		{name: "windows rejects macOS team ids", goos: "windows", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedTeamIDs = []string{"DE8Y96K9QP"}
		}, wantErr: "managed.allowed_team_ids"},
		{name: "windows rejects image outside the Secure Client tree", goos: "windows", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsImages = []string{`..\..\..\Users\Public\gui.exe`}
		}, wantErr: "managed.allowed_windows_images[0]"},
		{name: "windows rejects absolute image", goos: "windows", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsImages = []string{`C:\Users\Public\gui.exe`}
		}, wantErr: "managed.allowed_windows_images[0]"},
		{name: "windows rejects padded signer", goos: "windows", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsSigners = []string{"Cisco Systems, Inc. "}
		}, wantErr: "managed.allowed_windows_signers[0]"},
		{name: "darwin accepts macOS lists", goos: "darwin", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedTeamIDs = []string{"DE8Y96K9QP"}
		}},
		{name: "darwin rejects Windows signers", goos: "darwin", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsSigners = []string{"Cisco Systems, Inc."}
		}, wantErr: "managed.allowed_windows_signers"},
		{name: "linux rejects Windows images", goos: "linux", mode: "managed_enterprise", mutate: func(m *ManagedIPCConfig) {
			m.AllowedWindowsImages = []string{`UI\csc_ui.exe`}
		}, wantErr: "managed.allowed_windows_images"},
		{name: "unmanaged is not validated", goos: "windows", mode: "", mutate: func(m *ManagedIPCConfig) {
			m.AllowedTeamIDs = []string{"team"}
			m.AllowedWindowsImages = []string{`C:\evil.exe`}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DeploymentMode = tc.mode
			tc.mutate(&cfg.Managed)
			err := validateManagedIPCPeerAuthKnobs(cfg, tc.goos)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
