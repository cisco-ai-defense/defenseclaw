// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if err == nil ||
		!strings.Contains(err.Error(), "packaging-windows-enterprise-installer") ||
		!strings.Contains(err.Error(), "packaging-windows-avc-buildkit") {
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

func TestLoadEnterprisePayloadAcceptsStandaloneFlavors(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		payloadFS, manifest := newEnterprisePayloadFixtureForFlavor(t, unsigned, true)
		payload, err := loadEnterprisePayload(payloadFS)
		if err != nil {
			t.Fatalf("unsigned=%t: %v", unsigned, err)
		}
		if !payload.Standalone() || len(payload.Required) != len(standalonePayloadFiles) {
			t.Fatalf("payload %+v, manifest %+v", payload, manifest)
		}
		if _, broker := payload.Files["defenseclaw-cmid-broker.exe"]; broker {
			t.Fatal("the standalone payload must not carry the CMID broker")
		}
	}
	// A standalone manifest may not smuggle the broker back in.
	payloadFS, manifest := newEnterprisePayloadFixtureForFlavor(t, false, true)
	contents := []byte("broker")
	digest := sha256.Sum256(contents)
	payloadFS["payload/defenseclaw-cmid-broker.exe"] = &fstest.MapFile{Data: contents, Mode: 0o444}
	manifest.Files = append(manifest.Files, enterprisePayloadManifestFile{Name: "defenseclaw-cmid-broker.exe", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(contents))})
	writeEnterprisePayloadManifest(t, payloadFS, manifest)
	if _, err := loadEnterprisePayload(payloadFS); err == nil {
		t.Fatal("standalone payload with a broker was accepted")
	}
	// A Secure Client inventory labeled standalone is rejected.
	payloadFS, manifest = newEnterprisePayloadFixture(t, false)
	manifest.DistributionFlavor = standaloneFlavor
	writeEnterprisePayloadManifest(t, payloadFS, manifest)
	if _, err := loadEnterprisePayload(payloadFS); err == nil {
		t.Fatal("Secure Client inventory accepted as standalone")
	}
}

func TestParseEnterpriseSetupEnsureAndSigners(t *testing.T) {
	signer := "allowedsigners=" + strings.Repeat("AB", 32)
	opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", "config=C:\\c.yaml", signer})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Action != "ensure" || opts.Config != `C:\c.yaml` || opts.AllowedSigners != strings.Repeat("AB", 32) {
		t.Fatalf("opts %+v", opts)
	}
	if _, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", "--allowed-signers=nope"}); err == nil {
		t.Fatal("invalid signer accepted")
	}
	if _, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/status", "--no-start"}); err == nil ||
		err.Error() != "--no-start is valid only with install, upgrade, repair, or ensure" {
		t.Fatalf("standalone --no-start refusal = %v", err)
	}
}

// The Secure Client Setup keeps its own action set and flags: ensure and
// --allowed-signers are argument errors there, worded as before the
// standalone flavor existed.
func TestSecureClientSetupRejectsStandaloneArguments(t *testing.T) {
	for arguments, want := range map[string]string{
		"/ensure":         `unexpected positional argument "/ensure"`,
		"--action=ensure": "--action must be install, upgrade, repair, reconcile, status, verify, or uninstall",
		"--allowed-signers=" + strings.Repeat("ab", 32): "flag provided but not defined: -allowed-signers",
	} {
		_, _, err := parseEnterpriseSetupOptions([]string{arguments})
		if err == nil || err.Error() != want {
			t.Errorf("parseEnterpriseSetupOptions(%q) error = %v, want %q", arguments, err, want)
		}
	}
	_, _, err := parseEnterpriseSetupOptions([]string{"/install", "--config=a", "--manifest=b", "ALLOWEDSIGNERS=" + strings.Repeat("ab", 32)})
	if err == nil || !strings.HasPrefix(err.Error(), "unexpected positional argument") {
		t.Fatalf("Secure Client ALLOWEDSIGNERS= must stay an unknown argument: %v", err)
	}
}

func TestRunEnterpriseSetupHelpMatchesEmbeddedFlavor(t *testing.T) {
	previous := enterpriseSetupStandaloneFlavor
	t.Cleanup(func() { enterpriseSetupStandaloneFlavor = previous })
	for _, standalone := range []bool{false, true} {
		enterpriseSetupStandaloneFlavor = func() bool { return standalone }
		var stdout, stderr, want bytes.Buffer
		if code := runEnterpriseSetup([]string{"/?"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("standalone=%v: help exit=%d stderr=%q", standalone, code, stderr.String())
		}
		writeEnterpriseSetupUsageForFlavor(&want, standalone)
		if stdout.String() != want.String() {
			t.Fatalf("standalone=%v: usage = %q, want %q", standalone, stdout.String(), want.String())
		}
		if got := strings.Contains(stdout.String(), "ensure"); got != standalone {
			t.Fatalf("standalone=%v: usage lists ensure = %v", standalone, got)
		}
	}
	var secureClient bytes.Buffer
	writeEnterpriseSetupUsage(&secureClient)
	if want := enterpriseSetupArtifactName + " --action <install|reconcile|repair|status|uninstall|upgrade|verify> [options]\n" +
		"Install requires --config <config.yaml> and --manifest <targets.yaml>.\n" +
		"Production paths and service names are fixed by the enterprise lifecycle.\n"; secureClient.String() != want {
		t.Fatalf("Secure Client usage = %q", secureClient.String())
	}
}

// GAP-0353: the standalone Setup printed the Secure Client Setup name and
// --action flags for /?, and "unexpected positional argument BOGUS=1" for an
// unknown property, while windows.mdx documents /ensure NAME=value.
func TestStandaloneSetupUsageAndErrorsSpeakTheDocumentedSyntax(t *testing.T) {
	previous := enterpriseSetupStandaloneFlavor
	t.Cleanup(func() { enterpriseSetupStandaloneFlavor = previous })
	enterpriseSetupStandaloneFlavor = func() bool { return true }
	var usage, stderr bytes.Buffer
	if code := runEnterpriseSetup([]string{"/?"}, &usage, &stderr); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	for _, want := range []string{standaloneSetupArtifactName + " /ensure [NAME=value ...]", "CONFIG=", "MANIFEST=", "JSON=1", "NOSTART=1",
		"PURGE=1", "TIMEOUTSECONDS=", "ALLOWEDSIGNERS=", "ATTESTCLAUDEEFFECTIVEPOLICY=1"} {
		if !strings.Contains(usage.String(), want) {
			t.Errorf("standalone usage lacks %q:\n%s", want, usage.String())
		}
	}
	if strings.Contains(usage.String(), enterpriseSetupArtifactName) || strings.Contains(usage.String(), "--action") {
		t.Errorf("standalone usage names the Secure Client Setup or --action:\n%s", usage.String())
	}
	var stdout bytes.Buffer
	stderr.Reset()
	runEnterpriseSetup([]string{"/ensure", "BOGUS=1", "JSON=0"}, &stdout, &stderr)
	if got := stderr.String(); !strings.HasPrefix(got, standaloneSetupArtifactName+": unknown property BOGUS; run ") || !strings.Contains(got, " /? ") {
		t.Fatalf("unknown property error = %q", got)
	}
}

func TestEmbeddedSetupFlavorDefaultsToSecureClient(t *testing.T) {
	// The source tree embeds only the placeholder, which is not a
	// standalone manifest.
	if embeddedEnterpriseSetupStandalone() {
		t.Fatal("a Setup without a standalone manifest must parse as the Secure Client Setup")
	}
}

func newEnterprisePayloadFixture(t *testing.T, unsigned bool) (fstest.MapFS, enterprisePayloadManifest) {
	return newEnterprisePayloadFixtureForFlavor(t, unsigned, false)
}

func newEnterprisePayloadFixtureForFlavor(t *testing.T, unsigned, standalone bool) (fstest.MapFS, enterprisePayloadManifest) {
	t.Helper()
	files := requiredPayloadFiles
	if standalone {
		files = standalonePayloadFiles
	}
	payloadFS := make(fstest.MapFS, len(files)+1)
	entries := make([]enterprisePayloadManifestFile, 0, len(files))
	for _, name := range files {
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
	if standalone {
		flavor = standaloneFlavor
		if unsigned {
			flavor = standaloneUnsignedFlavor
		}
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

func TestSplitStandaloneLifecycleJSONKeepsOnlyTheResultOnStdout(t *testing.T) {
	output := []byte("WARNING: sonic/ast only supports go1.17~1.26\r\n{\"schema_version\":2,\"ok\":true}\r\n")
	document, diagnostics := splitStandaloneLifecycleJSON(output)
	if string(document) != "{\"schema_version\":2,\"ok\":true}\n" {
		t.Fatalf("document = %q", document)
	}
	if string(diagnostics) != "WARNING: sonic/ast only supports go1.17~1.26\n" {
		t.Fatalf("diagnostics = %q", diagnostics)
	}
	plain := []byte("not json at all\n")
	document, diagnostics = splitStandaloneLifecycleJSON(plain)
	if string(document) != string(plain) || diagnostics != nil {
		t.Fatalf("plain output = %q / %q, want it unchanged", document, diagnostics)
	}
}

// A command line that does not parse can never succeed on retry. The
// standalone Setup reports it as 1639 so an MDM stops retrying; the Secure
// Client Setup keeps its 0-or-1603 contract.
func TestRunEnterpriseSetupReportsBadCommandLinesByFlavor(t *testing.T) {
	original := enterpriseSetupPayloadLoader
	t.Cleanup(func() { enterpriseSetupPayloadLoader = original })
	for _, tc := range []struct {
		name       string
		standalone bool
		missing    bool
		want       int
	}{
		{name: "standalone", standalone: true, want: 1639},
		{name: "secure client", want: 1603},
		{name: "no embedded payload", missing: true, want: 1603},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missing {
				enterpriseSetupPayloadLoader = func() (enterprisePayload, error) {
					return enterprisePayload{}, errors.New("enterprise payload missing")
				}
			} else {
				payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, tc.standalone)
				enterpriseSetupPayloadLoader = func() (enterprisePayload, error) { return loadEnterprisePayload(payloadFS) }
			}
			for _, arguments := range [][]string{
				{"/ensure", "/bogus"},
				{"/ensure", "ALLOWEDSIGNERS=nothex"},
				{"/ensure", "PURGE=1"},
				{"/status", "NOSTART=1"},
				{"/install", "JSON=maybe"},
			} {
				var stdout, stderr bytes.Buffer
				if got := runEnterpriseSetup(arguments, &stdout, &stderr); got != tc.want {
					t.Fatalf("%q exit %d, want %d (stderr %q)", arguments, got, tc.want, stderr.String())
				}
			}
		})
	}
}

// GAP-0920, GAP-1041: the standalone Setup takes FORCE=1 with /uninstall, the
// last resort for a transaction no run can recover, and refuses it with
// another action; the Secure Client Setup has no such property.
func TestStandaloneSetupForceIsAnUninstallProperty(t *testing.T) {
	opts, _, err := parseEnterpriseSetupOptionsForFlavor([]string{"/uninstall", "FORCE=1", "JSON=1"}, true)
	if err != nil || !opts.Force || opts.Action != "uninstall" {
		t.Fatalf("standalone /uninstall FORCE=1: opts %+v, err %v", opts, err)
	}
	if _, _, err := parseEnterpriseSetupOptionsForFlavor([]string{"/ensure", "FORCE=1"}, true); err == nil {
		t.Fatal("FORCE=1 with /ensure was accepted")
	}
	if _, _, err := parseEnterpriseSetupOptionsForFlavor([]string{"/uninstall", "FORCE=1"}, false); err == nil {
		t.Fatal("the Secure Client Setup accepted FORCE=1")
	}
}

// GAP-0562: with JSON=1 the standalone Setup reports a refusal of its own in
// the lifecycle's schema-2 shape (code, message, exit_code 1639), so an MDM
// reads one shape whoever refused; the Secure Client Setup keeps schema 1.
func TestStandaloneSetupNormalizationFailurePreservesJSON(t *testing.T) {
	previous := enterpriseSetupStandaloneFlavor
	t.Cleanup(func() { enterpriseSetupStandaloneFlavor = previous })
	enterpriseSetupStandaloneFlavor = func() bool { return true }
	original := enterpriseSetupPayloadLoader
	t.Cleanup(func() { enterpriseSetupPayloadLoader = original })
	payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, true)
	enterpriseSetupPayloadLoader = func() (enterprisePayload, error) { return loadEnterprisePayload(payloadFS) }
	var stdout, stderr bytes.Buffer
	code := runEnterpriseSetup([]string{"/ensure", "BOGUS=1", "JSON=1"}, &stdout, &stderr)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Action        string `json:"action"`
		ExitCode      int    `json:"exit_code"`
		Errors        []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != enterpriseInvalidArgsExitCode ||
		result.SchemaVersion != 2 || result.Action != "ensure" || result.ExitCode != code ||
		len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q parse=%v", code, stdout.String(), stderr.String(), err)
	}
}

func TestStandaloneSetupFailureUsesTheLifecycleResultShape(t *testing.T) {
	opts := enterpriseSetupOptions{Action: "ensure", JSON: true}
	refusal := enterpriseSetupInvalidArguments{errors.New("the config C:\\stage\\config.yaml is not protected")}
	var stdout, stderr bytes.Buffer
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName, opts, refusal, enterpriseInvalidArgsExitCode)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Action        string `json:"action"`
		ExitCode      int    `json:"exit_code"`
		Errors        []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.SchemaVersion != 2 || result.Action != "ensure" ||
		result.ExitCode != enterpriseInvalidArgsExitCode || len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" ||
		result.Errors[0].Message != refusal.Error() {
		t.Fatalf("standalone failure = %s (%v)", stdout.String(), err)
	}
	stdout.Reset()
	writeEnterpriseSetupFailureFor(&stdout, &stderr, false, enterpriseSetupArtifactName, opts, refusal, enterpriseFailureExitCode)
	if !strings.HasPrefix(stdout.String(), `{"schema_version":1,`) {
		t.Fatalf("Secure Client failure shape changed: %s", stdout.String())
	}
}

// GAP-0509: a run Setup stopped at TIMEOUTSECONDS can leave a transaction
// pending with the services stopped; its result says so and names the
// LocalSystem /ensure that recovers it, with the longest limit: leaving
// TIMEOUTSECONDS out keeps the default the run hit (GAP-1063).
func TestStandaloneSetupTimeoutNamesTheRecovery(t *testing.T) {
	opts := enterpriseSetupOptions{Action: "ensure", JSON: true, Config: `C:\stage\config.yaml`, LifecycleTimeout: time.Minute}
	var stdout, stderr bytes.Buffer
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName, opts,
		standaloneEnterpriseSetupTimeout(opts, context.DeadlineExceeded), enterpriseFailureExitCode)
	var result struct {
		ExitCode int `json:"exit_code"`
		Errors   []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.ExitCode != enterpriseFailureExitCode ||
		len(result.Errors) != 1 || result.Errors[0].Code != "lifecycle_timeout" ||
		!strings.Contains(result.Errors[0].Message, `as LocalSystem with /ensure CONFIG=C:\stage\config.yaml JSON=1 TIMEOUTSECONDS=7200`) ||
		!strings.Contains(result.Errors[0].Message, "TIMEOUTSECONDS=60") || strings.Contains(result.Errors[0].Message, "leaving TIMEOUTSECONDS out") {
		t.Fatalf("timeout result = %s (%v)", stdout.String(), err)
	}
}
