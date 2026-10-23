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

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
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

func TestParseEnterpriseSetupDefaultsEmptyInstallToDeferredConfiguration(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		"/quiet",
		"DEFERREDCONFIG=1",
	})
	if err != nil || help {
		t.Fatalf("parse deferred install: help=%v err=%v", help, err)
	}
	if !opts.DeferredConfig || opts.Config != "" || opts.Manifest != "" {
		t.Fatalf("deferred install = %+v", opts)
	}

	opts, help, err = parseEnterpriseSetupOptions([]string{"/install"})
	if err != nil || help || !opts.DeferredConfig {
		t.Fatalf("implicit deferred install: opts=%+v help=%v err=%v", opts, help, err)
	}
}

func TestParseEnterpriseSetupRejectsUnsafeScopeCombinations(t *testing.T) {
	tests := [][]string{
		{"/install", "--config", "config.yaml"},
		{"/install", "--manifest", "targets.yaml"},
		{"/install", "--deferred-config", "--config", "config.yaml", "--manifest", "targets.yaml"},
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

// The Secure Client Setup also manages GitHub Copilot (the CLI and the GitHub
// Copilot app); the standalone shorthand keeps its three connectors.
func TestParseEnterpriseSetupShorthandAcceptsCopilotOnSecureClient(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		"MODE=action",
		"CONNECTOR=codex,claudecode,cursor,copilot",
	})
	if err != nil || help || opts.Connector != "codex,claudecode,cursor,copilot" {
		t.Fatalf("Secure Client Copilot shorthand install: opts=%+v help=%v err=%v", opts, help, err)
	}
	_, _, err = parseStandaloneEnterpriseSetupOptions([]string{
		"/install",
		"MODE=action",
		"CONNECTOR=codex,copilot",
	})
	if err == nil || !strings.Contains(err.Error(), "supported: codex, claudecode, cursor.") {
		t.Fatalf("standalone Copilot shorthand error = %v, want the three-connector refusal", err)
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

// TestPlaceholderBuildFailsClosedWithoutEnterprisePayload asserts the
// runtime refuses to install when the outer EXE has no
// setuppayload trailer at its tail. Under `go test` the running
// binary is the test executable, which has no trailer — so the
// setuppayload.ErrTrailerMissing path is exercised. The failure
// message points the operator at DefenseClawAssembler.exe.
func TestPlaceholderBuildFailsClosedWithoutEnterprisePayload(t *testing.T) {
	_, err := loadEmbeddedEnterprisePayload()
	if err == nil || !strings.Contains(err.Error(), "DefenseClawAssembler.exe") {
		t.Fatalf("loadEmbeddedEnterprisePayload() error = %v", err)
	}
}

// #1281: the Setup stages only the payload its own image was built with. A
// trailer read from a different file (any flavor) is refused before
// anything is staged, and an image with no binding takes no standalone
// payload.
func TestEnterprisePayloadMustMatchTheImageBinding(t *testing.T) {
	trailer := func(t *testing.T, payloadFS fstest.MapFS) setuppayload.ReadResult {
		t.Helper()
		result := setuppayload.ReadResult{Manifest: payloadFS["payload/manifest.json"].Data}
		for name, file := range payloadFS {
			if name != "payload/manifest.json" {
				result.Entries = append(result.Entries, setuppayload.Entry{Name: strings.TrimPrefix(name, "payload/"), Contents: file.Data})
			}
		}
		return result
	}
	binding := func(manifest enterprisePayloadManifest) string {
		digests := map[string]string{}
		for _, file := range manifest.Files {
			digests[file.Name] = file.SHA256
		}
		return setuppayload.PayloadBinding(setuppayload.PayloadIdentity{
			DistributionFlavor: manifest.DistributionFlavor,
			Version:            manifest.Version,
			SourceCommit:       manifest.SourceCommit,
		}, digests)
	}
	built, builtManifest := newEnterprisePayloadFixtureForFlavor(t, true, true)
	stamp := binding(builtManifest)
	if _, err := loadBoundEnterprisePayload(trailer(t, built), stamp); err != nil {
		t.Fatalf("the image's own payload was refused: %v", err)
	}
	if _, err := loadBoundEnterprisePayload(trailer(t, built), strings.ToUpper(stamp)); err != nil {
		t.Fatalf("an upper-case binding was refused: %v", err)
	}

	// A different payload: one file swapped for other bytes.
	swapped, swappedManifest := newEnterprisePayloadFixtureForFlavor(t, true, true)
	marker := []byte("swapped-file marker")
	digest := sha256.Sum256(marker)
	swapped["payload/defenseclaw.exe"] = &fstest.MapFile{Data: marker, Mode: 0o444}
	for index, file := range swappedManifest.Files {
		if file.Name == "defenseclaw.exe" {
			swappedManifest.Files[index].SHA256, swappedManifest.Files[index].Size = hex.EncodeToString(digest[:]), int64(len(marker))
		}
	}
	writeEnterprisePayloadManifest(t, swapped, swappedManifest)
	if _, err := loadEnterprisePayload(swapped); err != nil {
		t.Fatalf("fixture: the swapped payload is not otherwise valid: %v", err)
	}
	// The same payload bytes under another manifest identity: a replacement
	// trailer that changes only the version (which the lifecycle compares
	// and records) or the source commit.
	relabeled := func(t *testing.T, change func(*enterprisePayloadManifest)) fstest.MapFS {
		t.Helper()
		payloadFS := fstest.MapFS{}
		for name, file := range built {
			payloadFS[name] = &fstest.MapFile{Data: append([]byte(nil), file.Data...), Mode: file.Mode}
		}
		manifest := builtManifest
		manifest.Files = append([]enterprisePayloadManifestFile(nil), builtManifest.Files...)
		change(&manifest)
		writeEnterprisePayloadManifest(t, payloadFS, manifest)
		if _, err := loadEnterprisePayload(payloadFS); err != nil {
			t.Fatalf("fixture: the relabeled payload is not otherwise valid: %v", err)
		}
		return payloadFS
	}
	for name, other := range map[string]fstest.MapFS{
		"swapped file": swapped,
		"version only": relabeled(t, func(manifest *enterprisePayloadManifest) { manifest.Version = "99.0.0" }),
		"source commit only": relabeled(t, func(manifest *enterprisePayloadManifest) {
			manifest.SourceCommit = strings.Repeat("e", 40)
		}),
		"signed flavor": func() fstest.MapFS {
			payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, true)
			return payloadFS
		}(),
		"Secure Client": func() fstest.MapFS {
			payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, false)
			return payloadFS
		}(),
		"Secure Client u": func() fstest.MapFS {
			payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, true, false)
			return payloadFS
		}(),
	} {
		if _, err := loadBoundEnterprisePayload(trailer(t, other), stamp); err == nil || !strings.Contains(err.Error(), "nothing was staged") {
			t.Errorf("%s: a payload the image was not built with was accepted (err %v)", name, err)
		}
	}

	// No binding: no standalone payload, the Secure Client flavors as before.
	if _, err := loadBoundEnterprisePayload(trailer(t, built), ""); err == nil || !strings.Contains(err.Error(), "no payload binding") {
		t.Fatalf("an unstamped image took a standalone payload (err %v)", err)
	}
	secureClient, _ := newEnterprisePayloadFixtureForFlavor(t, false, false)
	if _, err := loadBoundEnterprisePayload(trailer(t, secureClient), ""); err != nil {
		t.Fatalf("an unstamped image refused the Secure Client payload: %v", err)
	}
}

func TestStampedSetupImageIsTheStandaloneSetup(t *testing.T) {
	previous := standalonePayloadBinding
	t.Cleanup(func() { standalonePayloadBinding = previous })
	standalonePayloadBinding = strings.Repeat("ab", 32)
	if !embeddedEnterpriseSetupStandalone() {
		t.Fatal("a stamped image must parse its command line as the standalone Setup")
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

// A padded file property reaches the path checks as given, so they refuse
// it as "empty, relative, padded, or environment-expanded" (GAP-0632).
func TestStandaloneSetupKeepsAPaddedPath(t *testing.T) {
	opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `CONFIG=C:\c.yaml `, `MANIFEST=C:\t.yaml `, "JSON=1"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Config != `C:\c.yaml ` || opts.Manifest != `C:\t.yaml ` {
		t.Fatalf("config %q, manifest %q: the padding was dropped", opts.Config, opts.Manifest)
	}
	opts, _, err = parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `BUNDLE=C:\b\v7.dcbundle `, `TRUSTANCHORS=C:\b\a.json `})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Bundle != `C:\b\v7.dcbundle ` || opts.TrustAnchors != `C:\b\a.json ` {
		t.Fatalf("bundle %q, trust anchors %q: the padding was dropped", opts.Bundle, opts.TrustAnchors)
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
		"Install takes --config <config.yaml> and --manifest <targets.yaml> together; with neither, it stages a disabled deployment that a later Repair with both files activates.\n" +
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

// BUNDLE= and TRUSTANCHORS= are standalone /ensure properties; the signed
// bundle carries the config, so BUNDLE= with CONFIG= is invalid arguments,
// and the Secure Client Setup does not know them.
func TestStandaloneSetupBundleIsAnEnsureProperty(t *testing.T) {
	opts, _, err := parseEnterpriseSetupOptionsForFlavor([]string{"/ensure", `BUNDLE=C:\b\v7.dcbundle`, `TrustAnchors=C:\b\a.json`, "REFUSECAPABILITYLOSS=1", "JSON=1"}, true)
	if err != nil || opts.Bundle != `C:\b\v7.dcbundle` || opts.TrustAnchors != `C:\b\a.json` || !opts.RefuseCapabilityLoss {
		t.Fatalf("standalone /ensure BUNDLE=: opts %+v, err %v", opts, err)
	}
	for _, arguments := range [][]string{
		{"/ensure", `BUNDLE=C:\b\v7.dcbundle`, `CONFIG=C:\c.yaml`},
		{"/repair", `BUNDLE=C:\b\v7.dcbundle`},
		{"/status", `TRUSTANCHORS=C:\b\a.json`},
		{"/ensure", "REFUSECAPABILITYLOSS=1"},
	} {
		if _, _, err := parseEnterpriseSetupOptionsForFlavor(arguments, true); err == nil {
			t.Errorf("standalone %v was accepted", arguments)
		}
	}
	if _, _, err := parseEnterpriseSetupOptionsForFlavor([]string{"/install", "--config=a", "--manifest=b", `BUNDLE=C:\b\v7.dcbundle`}, false); err == nil {
		t.Fatal("the Secure Client Setup accepted BUNDLE=")
	}
}

func TestStandaloneSetupRefuseCapabilityLossNamesTheCorrectNextStep(t *testing.T) {
	t.Run("ensure without bundle", func(t *testing.T) {
		_, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", "REFUSECAPABILITYLOSS=1"})
		if err == nil {
			t.Fatal("REFUSECAPABILITYLOSS=1 was accepted without BUNDLE=")
		}
		for _, want := range []string{"REFUSECAPABILITYLOSS=1 requires BUNDLE=", "nothing was changed", "deliver both with Setup /ensure"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name %q", err, want)
			}
		}
	})
	for _, action := range []string{"install", "upgrade", "repair"} {
		for _, bundle := range []string{"", `BUNDLE=C:\b\v7.dcbundle`} {
			name := action
			arguments := []string{"/" + action, "REFUSECAPABILITYLOSS=1"}
			if bundle != "" {
				name += " with bundle"
				arguments = append(arguments, bundle)
			}
			t.Run(name, func(t *testing.T) {
				_, _, err := parseStandaloneEnterpriseSetupOptions(arguments)
				if err == nil {
					t.Fatal("REFUSECAPABILITYLOSS=1 was accepted outside /ensure")
				}
				for _, want := range []string{"REFUSECAPABILITYLOSS=1", "only with /ensure", "nothing was changed", "Setup /ensure"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal %q does not name %q", err, want)
					}
				}
				if bundle == "" {
					if !strings.Contains(err.Error(), "requires BUNDLE=") || !strings.Contains(err.Error(), "deliver both") {
						t.Errorf("missing bundle refusal %q does not name both inputs", err)
					}
				} else if strings.Contains(err.Error(), "requires BUNDLE=") || !strings.Contains(err.Error(), "deliver BUNDLE= and REFUSECAPABILITYLOSS=1") {
					t.Errorf("supplied bundle refusal %q names the wrong cause or next step", err)
				}
			})
		}
	}
}

// #1288 refuses anchors with an unsigned CONFIG= (or the --mode shorthand,
// which renders one) with bundle_required, exit 1639. Setup refused it over
// the command line, so the refused anchor install had no
// config.trust_anchors.changed row, which the defenseclaw.exe route leaves
// (GAP-0608). Setup now hands every TRUSTANCHORS= mutation to the lifecycle,
// which refuses it before it changes anything and records the refusal.
func TestStandaloneSetupLeavesTrustAnchorRefusalsToTheLifecycle(t *testing.T) {
	for _, arguments := range [][]string{
		{"/ensure", `TRUSTANCHORS=C:\b\a.json`, `CONFIG=C:\c.yaml`},
		{"/ensure", `CONFIG=C:\c.yaml`, `trust-anchors=C:\b\a.json`},
		{"/ensure", `TRUSTANCHORS=C:\b\a.json`, "--mode=action", "--connector=codex"},
		{"/ensure", `TRUSTANCHORS=C:\b\a.json`, `BUNDLE=C:\b\v7.dcbundle`, `CONFIG=C:\c.yaml`},
		{"/ensure", `TRUSTANCHORS=C:\b\a.json`, "REFUSECAPABILITYLOSS=1"},
		{"/repair", `TRUSTANCHORS=C:\b\a.json`},
		{"/ensure", `BUNDLE=C:\b\v7.dcbundle`, `TRUSTANCHORS=C:\b\a.json`},
		{"/ensure", `TRUSTANCHORS=C:\b\a.json`},
	} {
		opts, _, err := parseStandaloneEnterpriseSetupOptions(arguments)
		if err != nil || opts.TrustAnchors != `C:\b\a.json` {
			t.Errorf("standalone %v: err %v, anchors %q; want the run handed to the lifecycle", arguments, err, opts.TrustAnchors)
		}
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

func TestStandaloneSetupTimeoutReportsTheRecoveredDeployment(t *testing.T) {
	opts := enterpriseSetupOptions{Action: "ensure", JSON: true, LifecycleTimeout: time.Minute}
	recovered := enterprisestatus.New("recover", "standalone", "windows", "1.0.3")
	recovered.Installed = true
	recovered.InstalledVersion = "1.0.3"
	recovered.TransactionPending = false
	recovered.Services = append(recovered.Services, enterprisestatus.Service{
		Name: "DefenseClawGateway", Kind: "gateway", State: "running", Required: true,
	})
	recovered.Finish("windows", enterpriseFailureExitCode)
	var stdout, stderr bytes.Buffer
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName, opts,
		standaloneEnterpriseSetupTimeoutWithRecovery(opts, context.DeadlineExceeded, recovered), enterpriseFailureExitCode)
	var result struct {
		Action             string `json:"action"`
		OK                 bool   `json:"ok"`
		ExitCode           int    `json:"exit_code"`
		Installed          bool   `json:"installed"`
		InstalledVersion   string `json:"installed_version"`
		TransactionPending bool   `json:"transaction_pending"`
		Services           []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"services"`
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Action != "ensure" ||
		result.OK || result.ExitCode != enterpriseFailureExitCode || !result.Installed ||
		result.InstalledVersion != "1.0.3" || result.TransactionPending ||
		len(result.Services) != 1 || result.Services[0].Name != "DefenseClawGateway" ||
		result.Services[0].State != "running" || len(result.Errors) != 1 ||
		result.Errors[0].Code != "lifecycle_timeout" || stderr.Len() != 0 {
		t.Fatalf("timeout lost recovered deployment proof: %s (%v)", stdout.String(), err)
	}
}
