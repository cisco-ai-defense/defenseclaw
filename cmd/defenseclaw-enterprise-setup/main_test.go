// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestParseEnterpriseSetupInstallContract(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		`CONFIG=C:\staging\config.yaml`,
		`MANIFEST=C:\staging\targets.yaml`,
		"NOSTART=1",
		"JSON=true",
		"TIMEOUTSECONDS=600",
	})
	if err != nil {
		t.Fatal(err)
	}
	if help {
		t.Fatal("install arguments unexpectedly requested help")
	}
	if opts.Action != "install" || opts.Config != `C:\staging\config.yaml` ||
		opts.Manifest != `C:\staging\targets.yaml` || !opts.NoStart || !opts.JSON ||
		opts.LifecycleTimeout != 10*time.Minute {
		t.Fatalf("parsed options = %+v", opts)
	}
}

func TestParseEnterpriseSetupRejectsUnsafeScopeCombinations(t *testing.T) {
	tests := [][]string{
		{"/install", "--config", "config.yaml"},
		{"/status", "--no-start"},
		{"/repair", "--purge"},
		{"/install", "--config", "config.yaml", "--manifest", "targets.yaml", "--allow-unsigned"},
		{"/verify", "--timeout-seconds", "59"},
	}
	for _, arguments := range tests {
		if _, _, err := parseEnterpriseSetupOptions(arguments); err == nil {
			t.Errorf("parseEnterpriseSetupOptions(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestParseEnterpriseSetupAcceptsDeploymentSystemNoOps(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{"/quiet", "/norestart", "/status"})
	if err != nil || help {
		t.Fatalf("parse status: help=%v err=%v", help, err)
	}
	if opts.Action != "status" {
		t.Fatalf("action = %q, want status", opts.Action)
	}
}

// TestParseEnterpriseSetupShorthandAcceptsModeAndConnector pins the
// macOS-parity QA shorthand: MODE + CONNECTOR alone satisfy the install
// contract (config / manifest are rendered by install-enterprise.ps1
// inside its bootstrap staging directory).
func TestParseEnterpriseSetupShorthandAcceptsModeAndConnector(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		"MODE=action",
		"CONNECTOR=codex,claudecode",
		"JSON=1",
	})
	if err != nil || help {
		t.Fatalf("shorthand install: help=%v err=%v", help, err)
	}
	if opts.Action != "install" || opts.Mode != "action" ||
		opts.Connector != "codex,claudecode" || !opts.JSON {
		t.Fatalf("parsed = %+v", opts)
	}
	if opts.Config != "" || opts.Manifest != "" {
		t.Fatalf("shorthand must leave config/manifest empty, got %+v", opts)
	}

	opts, help, err = parseEnterpriseSetupOptions([]string{
		"/install",
		"MODE=action",
		"CONNECTOR=codex,claudecode,cursor",
	})
	if err != nil || help || opts.Connector != "codex,claudecode,cursor" {
		t.Fatalf("Cursor shorthand install: opts=%+v help=%v err=%v", opts, help, err)
	}
}

// TestParseEnterpriseSetupShorthandRejectsBadGrammar covers the
// mutual-exclusion and pairing invariants the shorthand enforces.
func TestParseEnterpriseSetupShorthandRejectsBadGrammar(t *testing.T) {
	tests := map[string][]string{
		"mode without connector": {"/install", "MODE=action"},
		"connector without mode": {"/install", "CONNECTOR=codex"},
		"mode + config":          {"/install", "MODE=action", "CONNECTOR=codex", "CONFIG=x.yaml"},
		"mode + manifest":        {"/install", "MODE=action", "CONNECTOR=codex", "MANIFEST=x.yaml"},
		"invalid mode":           {"/install", "MODE=paranoid", "CONNECTOR=codex"},
		"shorthand on status":    {"/status", "MODE=action", "CONNECTOR=codex"},
		"amp on windows":         {"/install", "MODE=action", "CONNECTOR=amp"},
	}
	for name, arguments := range tests {
		if _, _, err := parseEnterpriseSetupOptions(arguments); err == nil {
			t.Errorf("%s: parseEnterpriseSetupOptions(%q) unexpectedly succeeded", name, arguments)
		}
	}
}

func TestPlaceholderBuildFailsClosedWithoutEnterprisePayload(t *testing.T) {
	_, err := loadEmbeddedEnterprisePayload()
	if err == nil || !strings.Contains(err.Error(), "build-windows-enterprise-installer.ps1") {
		t.Fatalf("loadEmbeddedEnterprisePayload() error = %v", err)
	}
}

func TestLoadEnterprisePayloadAcceptsEmitterManifestContract(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		name := "signed"
		if unsigned {
			name = "unsigned"
		}
		t.Run(name, func(t *testing.T) {
			payloadFS, manifest := newEnterprisePayloadFixture(t, unsigned)
			payload, err := loadEnterprisePayload(payloadFS)
			if err != nil {
				t.Fatalf("loadEnterprisePayload(): %v", err)
			}
			if payload.Manifest.DistributionFlavor != manifest.DistributionFlavor ||
				payload.Manifest.Unsigned != unsigned {
				t.Fatalf("manifest = %+v, want flavor=%q unsigned=%t", payload.Manifest, manifest.DistributionFlavor, unsigned)
			}
			if len(payload.Files) != len(requiredPayloadFiles) {
				t.Fatalf("validated file count = %d, want %d", len(payload.Files), len(requiredPayloadFiles))
			}
			for _, entry := range manifest.Files {
				if got, ok := payload.Files[entry.Name]; !ok || got != entry {
					t.Errorf("validated file %q = %+v, %t; want %+v", entry.Name, got, ok, entry)
				}
			}
		})
	}
}

func TestLoadEnterprisePayloadRejectsInvalidEmitterManifestContract(t *testing.T) {
	tests := map[string]struct {
		mutate func(*enterprisePayloadManifest)
		want   string
	}{
		"unsigned flavor mismatch": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Unsigned = true
			},
			want: "identity is invalid",
		},
		"duplicate file": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Files[1] = manifest.Files[0]
			},
			want: "duplicate file",
		},
		"unexpected file": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Files[0].Name = "unexpected.exe"
			},
			want: "unexpected file",
		},
		"invalid hash": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Files[0].SHA256 = "not-a-sha256"
			},
			want: "invalid SHA-256",
		},
		"declared size mismatch": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Files[0].Size++
			},
			want: "size does not match manifest",
		},
		"missing file": {
			mutate: func(manifest *enterprisePayloadManifest) {
				manifest.Files = manifest.Files[:len(manifest.Files)-1]
			},
			want: "unexpected file inventory",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			payloadFS, manifest := newEnterprisePayloadFixture(t, false)
			test.mutate(&manifest)
			writeEnterprisePayloadManifest(t, payloadFS, manifest)
			if _, err := loadEnterprisePayload(payloadFS); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadEnterprisePayload() error = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestLoadEnterprisePayloadRejectsLegacyFilesMap(t *testing.T) {
	payloadFS, manifest := newEnterprisePayloadFixture(t, false)
	legacyFiles := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		legacyFiles[entry.Name] = entry.SHA256
	}
	legacyManifest := map[string]any{
		"schema_version":      manifest.SchemaVersion,
		"version":             manifest.Version,
		"source_commit":       manifest.SourceCommit,
		"distribution_flavor": manifest.DistributionFlavor,
		"unsigned":            manifest.Unsigned,
		"files":               legacyFiles,
	}
	manifestBytes, err := json.Marshal(legacyManifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadFS["payload/manifest.json"] = &fstest.MapFile{Data: manifestBytes, Mode: 0o444}
	if _, err := loadEnterprisePayload(payloadFS); err == nil || !strings.Contains(err.Error(), "parse embedded enterprise manifest") {
		t.Fatalf("loadEnterprisePayload() error = %v, want legacy schema rejection", err)
	}
}

func newEnterprisePayloadFixture(t *testing.T, unsigned bool) (fstest.MapFS, enterprisePayloadManifest) {
	t.Helper()
	payloadFS := make(fstest.MapFS, len(requiredPayloadFiles)+1)
	entries := make([]enterprisePayloadManifestFile, 0, len(requiredPayloadFiles))
	for _, name := range requiredPayloadFiles {
		contents := []byte("test payload for " + name)
		digest := sha256.Sum256(contents)
		entries = append(entries, enterprisePayloadManifestFile{
			Name:   name,
			SHA256: hex.EncodeToString(digest[:]),
			Size:   int64(len(contents)),
		})
		payloadFS["payload/"+name] = &fstest.MapFile{Data: contents, Mode: 0o444}
	}
	flavor := managedEnterpriseFlavor
	if unsigned {
		flavor = managedEnterpriseUnsignedFlavor
	}
	manifest := enterprisePayloadManifest{
		SchemaVersion:      1,
		Version:            "0.9.0-test",
		SourceCommit:       "1111222233334444555566667777888899990000",
		DistributionFlavor: flavor,
		Unsigned:           unsigned,
		Files:              entries,
	}
	writeEnterprisePayloadManifest(t, payloadFS, manifest)
	return payloadFS, manifest
}

func writeEnterprisePayloadManifest(t *testing.T, payloadFS fstest.MapFS, manifest enterprisePayloadManifest) {
	t.Helper()
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadFS["payload/manifest.json"] = &fstest.MapFile{Data: manifestBytes, Mode: 0o444}
}

func TestRunEnterpriseSetupHelpDoesNotInvokePlatform(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runEnterpriseSetup([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), enterpriseSetupArtifactName) || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
