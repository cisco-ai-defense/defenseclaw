// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// GAP-2095: a .codex linked to a share whose server cannot be reached (or a
// junction to a folder that is gone) reads as no config, since Go maps
// ERROR_BAD_NETPATH and a missing target to os.ErrNotExist. The take-back
// must treat it as a config it cannot read: keep the pending marker (and
// record one, revoking the credential, when the upgrade itself meets the
// unreachable share), never clear it.
func TestWindowsManagedNativeOTLPTakeBackKeepsThePendingMarkerWhenTheLinkedConfigCannotBeReached(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("e7", 32)
	body := "model = 'o4'\r\n[otel.exporter.otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/logs'\r\n" +
		"[otel.exporter.otlp-http.headers]\r\nauthorization = 'Bearer " + credential + "'\r\n"
	type account struct{ home, dataDir, share, token, marker string }
	newAccount := func(withCredential bool) account {
		t.Helper()
		a := account{home: t.TempDir()}
		a.dataDir = filepath.Join(a.home, ".defenseclaw")
		a.share = filepath.Join(t.TempDir(), "share")
		if err := os.MkdirAll(a.share, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(a.share, "config.toml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		makeTestJunction(t, filepath.Join(a.home, ".codex"), a.share)
		a.token, err = connector.OTLPPathTokenFilePath(a.dataDir, connector.OTLPScopeCodex)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(a.token), 0o700); err != nil {
			t.Fatal(err)
		}
		if withCredential {
			if err := os.WriteFile(a.token, []byte(credential), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		a.marker = filepath.Join(a.dataDir, "native-otlp-take-back-pending-codex.json")
		return a
	}
	var warnings []string
	previousWarn := windowsNativeOTLPWarn
	windowsNativeOTLPWarn = func(message string) { warnings = append(warnings, message) }
	t.Cleanup(func() { windowsNativeOTLPWarn = previousWarn })
	takeBack := func(a account) string {
		t.Helper()
		warnings = nil
		if err := connector.WithUserHomeDir(a.home, func() error {
			removeWindowsManagedUserNativeOTLPAsTarget("codex", user.User.Sid, a.home, a.dataDir)
			return nil
		}); err != nil {
			t.Fatalf("take-back failed the install: %v", err)
		}
		return strings.Join(warnings, "\n")
	}
	unreachable := func(a account) {
		t.Helper()
		if err := os.RemoveAll(a.share); err != nil {
			t.Fatal(err)
		}
	}

	// Pending (the signed-out upgrade could not read the share), then the
	// account signs in while the share cannot be reached.
	pending := newAccount(true)
	restore := denyWindowsTestPathReadForTest(t, filepath.Join(pending.share, "config.toml"), user.User.Sid)
	report := takeBack(pending)
	restore()
	if _, err := os.Lstat(pending.marker); err != nil {
		t.Fatalf("no pending marker after a failed take-back: %v (report %q)", err, report)
	}
	unreachable(pending)
	report = takeBack(pending)
	if _, err := os.Lstat(pending.marker); err != nil {
		t.Fatalf("take-back cleared the pending marker while the linked config cannot be reached: %v (report %q)", err, report)
	}
	if !strings.Contains(report, "cannot be reached") {
		t.Fatalf("take-back report = %q, want the unreachable link named", report)
	}

	// The upgrade itself meets the unreachable share: record the marker and
	// revoke the credential.
	offline := newAccount(true)
	unreachable(offline)
	report = takeBack(offline)
	if _, err := os.Lstat(offline.marker); err != nil {
		t.Fatalf("no pending marker for an unreachable linked config with a credential: %v (report %q)", err, report)
	}
	if _, err := os.Lstat(offline.token); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential kept beside an unreachable linked config: %v", err)
	}
	if err := windowsManagedUserNativeOTLPAbsent("codex", offline.home, offline.dataDir, user.User.Sid); err != nil {
		t.Fatalf("verify fails the install on the pending take-back: %v", err)
	}

	// The config FILE itself is a symlink to the share (.codex is a real
	// folder): a take-back that cannot read it records the marker; a retry
	// while the share cannot be reached keeps it.
	fileLinked := newAccount(true)
	if err := os.Remove(filepath.Join(fileLinked.home, ".codex")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fileLinked.home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fileLinked.share, "config.toml"), filepath.Join(fileLinked.home, ".codex", "config.toml")); err != nil {
		t.Fatalf("file symlink (needs SeCreateSymbolicLinkPrivilege): %v", err)
	}
	restoreFile := denyWindowsTestPathReadForTest(t, filepath.Join(fileLinked.share, "config.toml"), user.User.Sid)
	report = takeBack(fileLinked)
	restoreFile()
	if _, err := os.Lstat(fileLinked.marker); err != nil {
		t.Fatalf("no pending marker for a config.toml linked to a share it cannot read: %v (report %q)", err, report)
	}
	unreachable(fileLinked)
	report = takeBack(fileLinked)
	if _, err := os.Lstat(fileLinked.marker); err != nil {
		t.Fatalf("take-back cleared the pending marker while the linked config.toml cannot be reached: %v (report %q)", err, report)
	}
	if !strings.Contains(report, "cannot be reached") {
		t.Fatalf("file-link take-back report = %q, want the unreachable link named", report)
	}

	// No earlier per-user install (no credential, no marker): nothing to report.
	never := newAccount(false)
	unreachable(never)
	if report = takeBack(never); report != "" {
		t.Fatalf("take-back reported an account with nothing to take back: %q", report)
	}
	if _, err := os.Lstat(never.marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker for an account with nothing to take back: %v", err)
	}
}
