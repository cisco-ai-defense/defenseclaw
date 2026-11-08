// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// replaceRecord publishes content at path through a new file renamed over it,
// the way the guardian replaces its records.
func replaceRecord(t *testing.T, path string, content []byte) {
	t.Helper()
	staged := path + ".next"
	if err := os.WriteFile(staged, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
}

// swapAfterStat replaces the record each time its name is checked, up to
// swaps times, and counts the checks.
func swapAfterStat(t *testing.T, path string, swaps int, content []byte) *int {
	t.Helper()
	checks := 0
	restore := pathidentity.SetPinnedStatHookForTest(func(checked string) {
		if checked != path {
			return
		}
		checks++
		if checks <= swaps {
			replaceRecord(t, path, content)
		}
	})
	t.Cleanup(restore)
	return &checks
}

func TestPublishedRecordReadSurvivesAReplacementBetweenCheckAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := swapAfterStat(t, path, 2, []byte(`{"v":1}`))
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
	if err != nil || !exists || string(data) != `{"v":1}` {
		t.Fatalf("read after replacements = %q, exists=%t, %v; want the record", data, exists, err)
	}
	if *checks != 3 {
		t.Fatalf("name checked %d times, want 3 (two replaced, one stable)", *checks)
	}
}

func TestPublishedRecordReadFailsClosedNamingTheFileWhenItStaysSwapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	swapAfterStat(t, path, 1<<20, []byte(`{"v":1}`))
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
	if err == nil || data != nil || !exists {
		t.Fatalf("persistent swap = %q, exists=%t, %v; want a refusal", data, exists, err)
	}
	if !errors.Is(err, safefile.ErrReadIdentityChanged) ||
		!strings.Contains(err.Error(), "hook guardian activation") || !strings.Contains(err.Error(), path) {
		t.Fatalf("persistent swap error = %v; want it to name the record and its path", err)
	}
}

func TestPublishedRecordReadRefusesALinkOrAnotherTypeAtOnce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	directory := filepath.Join(dir, "directory.json")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, directory} {
		checks := 0
		restore := pathidentity.SetPinnedStatHookForTest(func(string) { checks++ })
		_, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, nil)
		restore()
		if err == nil || !exists || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("%s: exists=%t, %v; want a not-a-regular-file refusal", path, exists, err)
		}
		if checks > 1 {
			t.Fatalf("%s: name checked %d times, want one (no retry for a link or another type)", path, checks)
		}
	}
}

func TestPublishedRecordReadRefusesAnUntrustedRecordAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	trustCalls := 0
	_, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 1024, func(string) error {
		trustCalls++
		return errors.New("owner is not trusted")
	})
	if err == nil || !exists || trustCalls != 1 || !strings.Contains(err.Error(), "owner is not trusted") {
		t.Fatalf("untrusted record: exists=%t, %v after %d trust checks; want one refusal", exists, err, trustCalls)
	}
}

func TestPublishedRecordReadReportsAMissingRecordAsAbsent(t *testing.T) {
	data, exists, err := readEnterpriseHookPublishedRecord(filepath.Join(t.TempDir(), "none.json"), "hook guardian activation", 1024, nil)
	if err != nil || exists || data != nil {
		t.Fatalf("missing record = %q, exists=%t, %v; want absent with no error", data, exists, err)
	}
}

func TestPublishedRecordReadKeepsTheSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readEnterpriseHookPublishedRecord(path, "hook guardian activation", 16, nil); err == nil || !strings.Contains(err.Error(), "exceeds 16-byte limit") {
		t.Fatalf("oversized record error = %v; want the byte limit", err)
	}
}

func TestGuardianActivationStatusReadSurvivesTheGuardianRewrite(t *testing.T) {
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	dataDir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	activation := enterpriseHookGuardianActivation{
		Version:        enterpriseHookGuardianActivationVersion,
		ReconcileID:    strings.Repeat("b", 32),
		Manifest:       "targets.yaml",
		ManifestSHA256: strings.Repeat("a", sha256.Size*2),
		OK:             true,
	}
	body, err := json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(authorizationDir, hookGuardianActivationFile)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	swapAfterStat(t, path, 2, body)
	got, exists, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil || !exists || got.ReconcileID != activation.ReconcileID {
		t.Fatalf("activation read during rewrites = %+v, exists=%t, %v; want the record", got, exists, err)
	}
}
