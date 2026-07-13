// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRenameInstallTreeRetriesTransientErrors(t *testing.T) {
	for _, errno := range []syscall.Errno{5, 32, 33} {
		errno := errno
		t.Run(errno.Error(), func(t *testing.T) {
			transient := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: errno}
			calls := 0
			var sleeps []time.Duration
			err := renameInstallTreeWith("old", "new", func(_, _ string) error {
				calls++
				if calls == 1 {
					return transient
				}
				return nil
			}, func(delay time.Duration) {
				sleeps = append(sleeps, delay)
			})
			if err != nil {
				t.Fatalf("renameInstallTreeWith: %v", err)
			}
			if calls != 2 {
				t.Fatalf("rename calls = %d, want 2", calls)
			}
			if len(sleeps) != 1 || sleeps[0] != installTreeRenameRetryDelay {
				t.Fatalf("sleep calls = %v, want [%s]", sleeps, installTreeRenameRetryDelay)
			}
		})
	}
}

func TestRenameInstallTreeDoesNotRetryPermanentErrors(t *testing.T) {
	for _, permanent := range []error{
		&os.LinkError{Op: "rename", Old: "old", New: "new", Err: syscall.Errno(2)},
		&os.LinkError{Op: "rename", Old: "old", New: "new", Err: syscall.Errno(13)},
		&os.LinkError{Op: "rename", Old: "old", New: "new", Err: syscall.Errno(87)},
		&os.LinkError{Op: "rename", Old: "old", New: "new", Err: syscall.Errno(183)},
		errors.New("permanent rename failure"),
	} {
		permanent := permanent
		t.Run(permanent.Error(), func(t *testing.T) {
			calls := 0
			sleeps := 0
			got := renameInstallTreeWith("old", "new", func(_, _ string) error {
				calls++
				return permanent
			}, func(time.Duration) { sleeps++ })
			if got != permanent {
				t.Fatalf("error = %v, want original %v", got, permanent)
			}
			if calls != 1 || sleeps != 0 {
				t.Fatalf("calls = %d, sleeps = %d; want 1, 0", calls, sleeps)
			}
		})
	}
}

func TestRenameInstallTreeStopsAtRetryBound(t *testing.T) {
	transient := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: syscall.Errno(5)}
	calls := 0
	var sleeps []time.Duration
	got := renameInstallTreeWith("old", "new", func(_, _ string) error {
		calls++
		return transient
	}, func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	})
	if got != transient || !errors.Is(got, syscall.Errno(5)) {
		t.Fatalf("error = %v, want original access-denied error", got)
	}
	if calls != installTreeRenameMaxAttempts {
		t.Fatalf("rename calls = %d, want %d", calls, installTreeRenameMaxAttempts)
	}
	if len(sleeps) != installTreeRenameMaxAttempts-1 {
		t.Fatalf("sleep calls = %d, want %d", len(sleeps), installTreeRenameMaxAttempts-1)
	}
	for index, delay := range sleeps {
		if delay != installTreeRenameRetryDelay {
			t.Fatalf("sleep[%d] = %s, want %s", index, delay, installTreeRenameRetryDelay)
		}
	}
}

func TestRenameInstallTreeReturnsImmediatelyOnSuccess(t *testing.T) {
	calls := 0
	sleeps := 0
	if err := renameInstallTreeWith("old", "new", func(_, _ string) error {
		calls++
		return nil
	}, func(time.Duration) { sleeps++ }); err != nil {
		t.Fatalf("renameInstallTreeWith: %v", err)
	}
	if calls != 1 || sleeps != 0 {
		t.Fatalf("calls = %d, sleeps = %d; want 1, 0", calls, sleeps)
	}
}

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

func TestParseArgsQuietPropertyMatrix(t *testing.T) {
	for _, connector := range []string{"none", "codex", "claudecode"} {
		for _, mode := range []string{"observe", "action"} {
			for _, start := range []string{"0", "1"} {
				t.Run(connector+"/"+mode+"/start-"+start, func(t *testing.T) {
					opts, err := parseArgs([]string{
						"/quiet",
						"CONNECTOR=" + connector,
						"MODE=" + mode,
						"STARTGATEWAY=" + start,
					})
					if err != nil {
						t.Fatalf("parseArgs returned error: %v", err)
					}
					wantStart := start == "1"
					if !opts.Quiet || opts.Connector != connector || opts.Mode != mode || opts.StartGateway != wantStart {
						t.Fatalf("quiet property matrix parsed incorrectly: %+v", opts)
					}
					if !opts.ConnectorSet || !opts.ModeSet || !opts.StartGatewaySet {
						t.Fatalf("quiet property matrix omitted explicit markers: %+v", opts)
					}
				})
			}
		}
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

func TestConfiguredConnectorRequiresPersistentGateway(t *testing.T) {
	for _, connectorName := range []string{"codex", "claudecode"} {
		wanted := requestedServices(options{Connector: connectorName}, serviceState{})
		if !wanted.Gateway {
			t.Fatalf("connector %s did not require gateway startup", connectorName)
		}
	}
	if wanted := requestedServices(options{Connector: "none"}, serviceState{}); wanted.Gateway {
		t.Fatal("CLI-only install unexpectedly required gateway startup")
	}
}

func TestOrdinaryInstallOfNewerPackageRunsMigrations(t *testing.T) {
	state := &installState{Version: "0.8.3"}
	if got := migrationSource(state, "0.8.4", ""); got != "0.8.3" {
		t.Fatalf("migration source = %q, want installed version", got)
	}
	if got := migrationSource(state, "0.8.3", ""); got != "" {
		t.Fatalf("equal-version repair unexpectedly selected migrations from %q", got)
	}
	if got := migrationSource(state, "0.8.4", "0.7.9"); got != "0.7.9" {
		t.Fatalf("explicit migration source = %q", got)
	}
}

func TestConnectorsForNativeUninstallUsesDurableBackups(t *testing.T) {
	dataRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataRoot, "claudecode_backup.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := connectorsForNativeUninstall(&installState{Connector: "codex"}, dataRoot)
	want := []string{"codex", "claudecode"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("connectors = %v, want %v", got, want)
	}
}

func TestGatewayAutoStartCommandQuotesPath(t *testing.T) {
	path := `C:\Users\Jane Doe\DefenseClaw\defenseclaw-gateway.exe`
	if got, want := gatewayAutoStartCommand(path), `"C:\Users\Jane Doe\DefenseClaw\defenseclaw-gateway.exe" start`; got != want {
		t.Fatalf("auto-start command = %q, want %q", got, want)
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
	t.Setenv("PYTHONUTF8", "0")
	t.Setenv("PYTHONIOENCODING", "cp1252")
	env := managedChildEnv(`C:\Users\test\.defenseclaw`)
	counts := map[string]int{}
	for _, entry := range env {
		if entry == `DEFENSECLAW_HOME=C:\untrusted` {
			t.Fatal("ambient data root survived managedChildEnv")
		}
		if entry == "PYTHONUTF8=0" || entry == "PYTHONIOENCODING=cp1252" {
			t.Fatalf("ambient Python encoding survived managedChildEnv: %q", entry)
		}
		counts[entry]++
	}
	for _, want := range []string{
		`DEFENSECLAW_HOME=C:\Users\test\.defenseclaw`,
		"PYTHONUTF8=1",
		"PYTHONIOENCODING=utf-8",
	} {
		if counts[want] != 1 {
			t.Fatalf("managed environment count for %q = %d, want 1", want, counts[want])
		}
	}
}

func TestPackagedMigrationCommandForcesUTF8UnderIsolation(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "profile", ".defenseclaw")
	openClawRoot := filepath.Join(root, "profile", ".openclaw")
	cmd := newPackagedMigrationCommand(context.Background(), root, dataRoot, openClawRoot, "0.7.0", "0.8.0")

	wantPrefix := []string{
		filepath.Join(root, "runtime", "python", "python.exe"),
		"-I",
		"-X",
		"utf8",
		"-c",
		packagedMigrationScript,
	}
	if len(cmd.Args) < len(wantPrefix) {
		t.Fatalf("packaged migration args = %v, want prefix %v", cmd.Args, wantPrefix)
	}
	for index, want := range wantPrefix {
		if got := cmd.Args[index]; got != want {
			t.Fatalf("packaged migration arg %d = %q, want %q; args=%v", index, got, want, cmd.Args)
		}
	}

	wantEnv := map[string]bool{
		"DEFENSECLAW_HOME=" + dataRoot: false,
		"PYTHONUTF8=1":                 false,
		"PYTHONIOENCODING=utf-8":       false,
	}
	for _, entry := range cmd.Env {
		if _, ok := wantEnv[entry]; ok {
			wantEnv[entry] = true
		}
	}
	for entry, found := range wantEnv {
		if !found {
			t.Fatalf("packaged migration environment is missing %q", entry)
		}
	}
}

func TestRunCapturedSetupCommandTimesOut(t *testing.T) {
	const helperEnv = "DEFENSECLAW_SETUP_TIMEOUT_TEST_HELPER"
	if os.Getenv(helperEnv) == "1" {
		time.Sleep(10 * time.Second)
		return
	}

	env := append(os.Environ(), helperEnv+"=1")
	started := time.Now()
	_, err := runCapturedSetupCommand(100*time.Millisecond, env, os.Args[0], "-test.run=^TestRunCapturedSetupCommandTimesOut$")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runCapturedSetupCommand error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("timed-out setup command returned after %s, want a bounded wait", elapsed)
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
