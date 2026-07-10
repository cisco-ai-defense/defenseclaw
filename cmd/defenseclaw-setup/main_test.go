// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseArgsSilentInstallProperties(t *testing.T) {
	opts, err := parseArgs([]string{
		"/quiet",
		"/norestart",
		"INSTALLSCOPE=user",
		"CONNECTOR=codex",
		"MODE=action",
		"STARTGATEWAY=1",
	})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if !opts.Quiet || !opts.NoRestart || !opts.StartGateway {
		t.Fatalf("flags not parsed: %+v", opts)
	}
	if opts.InstallScope != "user" || opts.Connector != "codex" || opts.Mode != "action" {
		t.Fatalf("properties not parsed: %+v", opts)
	}
	if !opts.ConnectorSet || !opts.ModeSet || !opts.StartGatewaySet {
		t.Fatalf("explicit property markers not parsed: %+v", opts)
	}
}

func TestParseArgsWaitPID(t *testing.T) {
	opts, err := parseArgs([]string{"WAITPID=42", "FROMVERSION=1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.WaitPID != 42 {
		t.Fatalf("WaitPID = %d, want 42", opts.WaitPID)
	}
	if opts.FromVersion != "1.2.3" {
		t.Fatalf("FromVersion = %q, want 1.2.3", opts.FromVersion)
	}
	if _, err := parseArgs([]string{"WAITPID=not-a-pid"}); err == nil {
		t.Fatal("parseArgs accepted an invalid WAITPID")
	}
}

func TestCompareVersionsRejectsDowngrade(t *testing.T) {
	if compareVersions("1.9.9", "2.0.0") >= 0 {
		t.Fatal("compareVersions did not order older release first")
	}
	if compareVersions("2.0.0", "2.0.0") != 0 {
		t.Fatal("compareVersions did not report equal releases")
	}
}

func TestNoRestartStillRestartsPreviouslyRunningOwnedServices(t *testing.T) {
	wanted := requestedServices(
		options{NoRestart: true},
		serviceState{Gateway: true, Watchdog: true},
	)
	if !wanted.Gateway || !wanted.Watchdog {
		t.Fatalf("previously running services were not preserved: %+v", wanted)
	}
}

func TestParseArgsRejectsMachineScope(t *testing.T) {
	if _, err := parseArgs([]string{"INSTALLSCOPE=machine"}); err == nil {
		t.Fatal("machine-wide install should require a separate enterprise MSI path")
	}
}

func TestParseArgsRejectsInvalidBooleanProperties(t *testing.T) {
	for _, property := range []string{"STARTGATEWAY=maybe", "DELETEUSERDATA=enabled"} {
		if _, err := parseArgs([]string{property}); err == nil {
			t.Fatalf("parseArgs accepted invalid boolean property %q", property)
		}
	}
}

func TestParseArgsConnectorLaterNormalizesToNone(t *testing.T) {
	opts, err := parseArgs([]string{"CONNECTOR=configure later"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if opts.Connector != "none" {
		t.Fatalf("connector = %q, want none", opts.Connector)
	}
}

func TestSafeJoinRejectsTraversalAndAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	unsafePaths := []string{
		"../escape.txt",
		`..\escape.txt`,
		filepath.Join(root, "absolute.txt"),
		"/rooted/payload.txt",
		`\rooted\payload.txt`,
		`C:payload\file.txt`,
		`C:\payload\file.txt`,
		"C:/payload/file.txt",
		`\\server\share\payload.txt`,
		"//server/share/payload.txt",
		"payload/file.txt:stream",
	}
	for _, unsafePath := range unsafePaths {
		if _, err := safeJoin(root, unsafePath); err == nil {
			t.Fatalf("safeJoin accepted unsafe path %q", unsafePath)
		}
	}
}

func TestSafeJoinAcceptsNestedPayloadPath(t *testing.T) {
	root := t.TempDir()
	got, err := safeJoin(root, "payload/nested/file.txt")
	if err != nil {
		t.Fatalf("safeJoin returned error: %v", err)
	}
	want := filepath.Join(root, "payload", "nested", "file.txt")
	if got != want {
		t.Fatalf("safeJoin = %q, want %q", got, want)
	}
}

func TestSafeJoinAcceptsNestedBackslashPayloadPath(t *testing.T) {
	root := t.TempDir()
	got, err := safeJoin(root, `payload\nested\file.txt`)
	if err != nil {
		t.Fatalf("safeJoin returned error: %v", err)
	}
	want := filepath.Join(root, "payload", "nested", "file.txt")
	if got != want {
		t.Fatalf("safeJoin = %q, want %q", got, want)
	}
}

func TestSanitizePythonEnvRemovesAmbientPythonVariables(t *testing.T) {
	env := sanitizePythonEnv([]string{
		"PYTHONHOME=C:/other",
		"PYTHONPATH=C:/checkout",
		"Path=C:/Windows",
		"DEFENSECLAW_HOME=C:/Users/example/.defenseclaw",
	})
	for _, entry := range env {
		if entry == "PYTHONHOME=C:/other" || entry == "PYTHONPATH=C:/checkout" {
			t.Fatalf("ambient Python variable survived: %v", env)
		}
	}
	if len(env) != 2 {
		t.Fatalf("env length = %d, want 2: %v", len(env), env)
	}
}

func TestManagedChildEnvPinsDataRoot(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", `C:\untrusted`)
	env := managedChildEnv(`C:\Users\test\.defenseclaw`)
	count := 0
	for _, entry := range env {
		if entry == `DEFENSECLAW_HOME=C:\Users\test\.defenseclaw` {
			count++
		}
		if entry == `DEFENSECLAW_HOME=C:\untrusted` {
			t.Fatal("ambient data root survived managedChildEnv")
		}
	}
	if count != 1 {
		t.Fatalf("managed data root count = %d, want 1", count)
	}
}

func TestValidPayloadVersion(t *testing.T) {
	for _, value := range []string{"0.8.0", "1.2.3-rc.1"} {
		if !validPayloadVersion(value) {
			t.Fatalf("validPayloadVersion(%q) = false", value)
		}
	}
	for _, value := range []string{
		"latest",
		"1.2",
		`1.2.3/escape`,
		"1.2.3-rc 1",
		"999999999999999999999.2.3",
	} {
		if validPayloadVersion(value) {
			t.Fatalf("validPayloadVersion(%q) = true", value)
		}
	}
}

func TestReadJSONRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{} {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := readJSON(path, &value); err == nil {
		t.Fatal("readJSON accepted a trailing JSON document")
	}
}

func TestExtractZipReaderRejectsExpandedSizeLimit(t *testing.T) {
	header := zip.FileHeader{Name: "oversized.bin", UncompressedSize64: uint64(maxZipExpandedBytes) + 1}
	reader := &zip.Reader{File: []*zip.File{{FileHeader: header}}}
	if err := extractZipReader(reader, t.TempDir()); err == nil {
		t.Fatal("extractZipReader accepted oversized metadata")
	}
}

func TestVerifyPayloadManifestRejectsMissingRequiredHash(t *testing.T) {
	manifest := payloadManifest{
		SchemaVersion:      1,
		Version:            "1.2.3",
		SourceCommit:       "0123456789abcdef0123456789abcdef01234567",
		DistributionFlavor: "oss",
		GatewayArchive:     "gateway.zip",
		Wheel:              "defenseclaw.whl",
		PythonEmbed:        "python.zip",
		SitePackages:       "site-packages.zip",
		Launcher:           "launcher.exe",
		UpgradeManifest:    "upgrade-manifest.json",
		Files:              map[string]string{},
	}
	if err := verifyPayloadManifest(t.TempDir(), manifest); err == nil {
		t.Fatal("verifyPayloadManifest accepted missing required hashes")
	}
}

func TestVerifyPayloadManifestRejectsInvalidSourceCommit(t *testing.T) {
	manifest := payloadManifest{
		SchemaVersion:      1,
		Version:            "1.2.3",
		SourceCommit:       "not-a-git-commit",
		DistributionFlavor: "oss",
	}
	if err := verifyPayloadManifest(t.TempDir(), manifest); err == nil {
		t.Fatal("verifyPayloadManifest accepted an invalid source commit")
	}
}

func TestValidSourceCommitRequiresExactLowercaseGitOID(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef01234567"
	if !validSourceCommit(valid) {
		t.Fatal("validSourceCommit rejected a 40-character lowercase Git object ID")
	}
	for _, invalid := range []string{
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"0123456789abcdef0123456789abcdef0123456",
		"0123456789abcdef0123456789abcdef012345678",
		"g123456789abcdef0123456789abcdef01234567",
	} {
		if validSourceCommit(invalid) {
			t.Fatalf("validSourceCommit accepted %q", invalid)
		}
	}
}

func TestVerifyPayloadManifestRejectsManagedEnterpriseWithoutOverlay(t *testing.T) {
	manifest := payloadManifest{
		SchemaVersion:      1,
		Version:            "1.2.3",
		SourceCommit:       "0123456789abcdef0123456789abcdef01234567",
		DistributionFlavor: "managed-enterprise",
	}
	if err := verifyPayloadManifest(t.TempDir(), manifest); err == nil {
		t.Fatal("verifyPayloadManifest accepted a managed-enterprise payload without the private Windows CMID overlay")
	}
}

func TestRemoveAllSafeRefusesEscapes(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeAllSafe(outside, root); err == nil {
		t.Fatal("removeAllSafe accepted path outside managed root")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was modified: %v", err)
	}
}
