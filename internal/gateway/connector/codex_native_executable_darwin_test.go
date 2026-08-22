// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeCodexDarwinFixture(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(path, append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("codex")...), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func validCodexDarwinSignatureDetail() string {
	return "Identifier=codex\n" +
		"Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)\n" +
		"TeamIdentifier=2DC432GLL2\n"
}

func stubCodexDarwinIdentity(
	t *testing.T,
	detail string,
	quarantine string,
	quarantineErr error,
) {
	t.Helper()
	previousCommand := runCodexDarwinIdentityCommand
	previousQuarantine := readCodexDarwinQuarantine
	previousFileACLValidator := validateCodexDarwinFileACL
	previousVersionProbe := probeCodexDarwinAgentVersion
	runCodexDarwinIdentityCommand = func(path string, args ...string) (string, error) {
		switch path {
		case "/usr/bin/codesign":
			if len(args) > 0 && args[0] == "-dvvv" {
				return detail, nil
			}
			return "", nil
		case "/usr/bin/lipo":
			arch := runtime.GOARCH
			if arch == "amd64" {
				arch = "x86_64"
			}
			return arch, nil
		default:
			return "", errors.New("unexpected command")
		}
	}
	readCodexDarwinQuarantine = func(string) (string, error) {
		return quarantine, quarantineErr
	}
	validateCodexDarwinFileACL = func(string) error { return nil }
	probeCodexDarwinAgentVersion = func(string, string, string) (string, error) {
		return "codex-cli 0.146.0", nil
	}
	t.Cleanup(func() {
		runCodexDarwinIdentityCommand = previousCommand
		readCodexDarwinQuarantine = previousQuarantine
		validateCodexDarwinFileACL = previousFileACLValidator
		probeCodexDarwinAgentVersion = previousVersionProbe
	})
}

func TestValidateCodexNativeExecutablePlatform(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o500)
	stubCodexDarwinIdentity(t, validCodexDarwinSignatureDetail(), "", unix.ENOATTR)
	if err := validateCodexNativeExecutablePlatform(path); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCodexNativeExecutableRejectsSpoofedTextWithoutAppleAnchor(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o500)
	stubCodexDarwinIdentity(t, validCodexDarwinSignatureDetail(), "", unix.ENOATTR)
	previous := runCodexDarwinIdentityCommand
	runCodexDarwinIdentityCommand = func(tool string, args ...string) (string, error) {
		if tool == "/usr/bin/codesign" && len(args) > 0 && args[0] == "--verify" {
			if !containsDarwinRequirementArg(args, "-R") || !containsDarwinRequirementArg(args, codexMacOSRequirement) {
				t.Fatalf("codesign verification lacks pinned requirement: %#v", args)
			}
			return "Identifier=codex\nTeamIdentifier=2DC432GLL2", errors.New("untrusted self-signed anchor")
		}
		return previous(tool, args...)
	}
	if err := validateCodexNativeExecutablePlatform(path); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("spoofed Codex signature error = %v", err)
	}
}

func containsDarwinRequirementArg(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestValidateCodexNativeExecutableVersionRejectsManifestMismatch(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o500)
	stubCodexDarwinIdentity(t, validCodexDarwinSignatureDetail(), "", unix.ENOATTR)
	_, digest, ok := setupSelectedAgentExecutableEvidence(path)
	if !ok {
		t.Fatal("cannot hash Codex fixture")
	}
	probeCodexDarwinAgentVersion = func(string, string, string) (string, error) {
		return "codex-cli 0.145.0", nil
	}
	err := validateCodexNativeExecutableVersionPlatform(path, "codex-cli 0.146.0", digest)
	if err == nil || !strings.Contains(err.Error(), "does not match protected version") {
		t.Fatalf("version mismatch error = %v, want refusal", err)
	}
}

func TestValidateCodexNativeExecutablePlatformRejectsNonExactSignatureIdentity(t *testing.T) {
	valid := validCodexDarwinSignatureDetail()
	for _, test := range []struct {
		name   string
		detail string
	}{
		{
			name:   "identifier suffix",
			detail: strings.Replace(valid, "Identifier=codex", "Identifier=codex-helper", 1),
		},
		{
			name:   "team suffix",
			detail: strings.Replace(valid, "TeamIdentifier=2DC432GLL2", "TeamIdentifier=2DC432GLL2-helper", 1),
		},
		{
			name:   "authority suffix",
			detail: strings.Replace(valid, "Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)", "Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2) helper", 1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCodexDarwinFixture(t, 0o500)
			stubCodexDarwinIdentity(t, test.detail, "", unix.ENOATTR)
			err := validateCodexNativeExecutablePlatform(path)
			if err == nil || !strings.Contains(err.Error(), "expected OpenAI Developer ID") {
				t.Fatalf("signature identity error = %v, want exact-identity refusal", err)
			}
		})
	}
}

func TestValidateCodexNativeExecutablePlatformRejectsUnsafeFileACL(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o500)
	previousFileACLValidator := validateCodexDarwinFileACL
	validateCodexDarwinFileACL = func(string) error { return errors.New("fixture file write-capable ACL") }
	t.Cleanup(func() { validateCodexDarwinFileACL = previousFileACLValidator })
	err := validateCodexNativeExecutablePlatform(path)
	if err == nil || !strings.Contains(err.Error(), "fixture file write-capable ACL") {
		t.Fatalf("unsafe file ACL error = %v, want ACL refusal", err)
	}
}

func TestValidateCodexNativeExecutablePlatformRejectsWritableMode(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o520)
	err := validateCodexNativeExecutablePlatform(path)
	if err == nil || !strings.Contains(err.Error(), "unsafe writable mode") {
		t.Fatalf("writable mode error = %v, want custody refusal", err)
	}
}

func TestValidateCodexNativeExecutablePlatformRejectsEmptyQuarantineAttribute(t *testing.T) {
	path := writeCodexDarwinFixture(t, 0o500)
	stubCodexDarwinIdentity(t, validCodexDarwinSignatureDetail(), "", nil)
	err := validateCodexNativeExecutablePlatform(path)
	if err == nil || !strings.Contains(err.Error(), "is quarantined") {
		t.Fatalf("empty quarantine attribute error = %v, want quarantine refusal", err)
	}
}

func TestCodexMacOSArchitectureListContains(t *testing.T) {
	for _, tc := range []struct {
		name     string
		output   string
		expected string
		want     bool
	}{
		{name: "thin arm", output: "arm64\n", expected: "arm64", want: true},
		{name: "thin intel rejected", output: "x86_64\n", expected: "arm64", want: false},
		{name: "universal host slice", output: "x86_64 arm64\n", expected: "arm64", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := codexMacOSArchitectureListContains(tc.output, tc.expected); got != tc.want {
				t.Fatalf("codexMacOSArchitectureListContains(%q, %q) = %v, want %v", tc.output, tc.expected, got, tc.want)
			}
		})
	}
}

func TestCodexDarwinSelectionAndLockSealExecutableCache(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "codex")
	if err := os.WriteFile(executable, append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("codex")...), 0o700); err != nil {
		t.Fatal(err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("cannot capture Codex executable evidence")
	}
	version := "codex 0.146.0"
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        stablePath,
				RawVersion:        version,
				NormalizedVersion: "0.146.0",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); got != stablePath {
		t.Fatalf("receipt-backed cached Codex executable = %q, want %q", got, stablePath)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != version {
		t.Fatalf("receipt-backed cached Codex version = %q, want %q", got, version)
	}

	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentExecutable: stablePath, AgentVersion: version},
		NewCodexConnector(),
		"test",
	)
	if entry.AgentExecutable != stablePath ||
		entry.AgentExecutableSource != "setup-selected" ||
		entry.AgentExecutableSHA256 != digest {
		t.Fatalf("protected Codex executable evidence = %#v", entry)
	}
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  entry.UpdatedAt,
		Connectors: map[string]HookContractLockEntry{"codex": entry},
	}
	body, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); got != stablePath {
		t.Fatalf("lock-backed cached Codex executable = %q, want %q", got, stablePath)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != version {
		t.Fatalf("lock-backed cached Codex version = %q, want %q", got, version)
	}
}
