// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnterpriseCredentialIsStableScopedAndRevocable(t *testing.T) {
	requireDirectEnterpriseCredentialTest(t)
	dataDir := t.TempDir()
	first, err := EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first.Token) != 64 {
		t.Fatalf("credential was not stable: first=%+v second=%+v", first, second)
	}
	matched, ok := MatchEnterpriseCredential(dataDir, first.Token)
	if !ok || matched.Principal != "uid:501" || matched.ClientID != "zed" ||
		matched.AgentID != "kiro" || matched.Profile != "locked" {
		t.Fatalf("matched credential = %+v, %v", matched, ok)
	}
	if _, ok := MatchEnterpriseCredential(dataDir, "not-a-token"); ok {
		t.Fatal("malformed credential matched")
	}
	if err := RemoveEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked"); err != nil {
		t.Fatal(err)
	}
	if _, ok := MatchEnterpriseCredential(dataDir, first.Token); ok {
		t.Fatal("revoked credential still matched")
	}
	reissued, err := EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if reissued.Token == first.Token {
		t.Fatal("re-enrollment reused a revoked credential")
	}
	if matched, ok := MatchEnterpriseCredential(dataDir, reissued.Token); !ok || matched != reissued {
		t.Fatalf("reissued credential did not match: %+v, %v", matched, ok)
	}
	if err := RemoveEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(enterpriseCredentialDir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("credential directory retains revocation artifacts: %v", entries)
	}
}

func TestEnterpriseCredentialRevocationTombstoneFailsInventoryClosed(t *testing.T) {
	requireDirectEnterpriseCredentialTest(t)
	dataDir := t.TempDir()
	credential, err := EnsureEnterpriseCredential(dataDir, "uid:503", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	path, err := EnterpriseCredentialPath(dataDir, "uid:503", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".revoked"); err != nil {
		t.Fatal(err)
	}
	if _, ok := MatchEnterpriseCredential(dataDir, credential.Token); ok {
		t.Fatal("credential matched while revocation tombstone was present")
	}
	if EnterpriseCredentialsReady(dataDir) {
		t.Fatal("credential inventory reported ready while revocation tombstone was present")
	}
}

func TestEnterpriseCredentialRevocationResumesIndexTombstoneCleanup(t *testing.T) {
	requireDirectEnterpriseCredentialTest(t)
	dataDir := t.TempDir()
	credential, err := EnsureEnterpriseCredential(dataDir, "uid:505", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	indexPath, err := EnterpriseCredentialIndexPath(dataDir, credential.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(indexPath, indexPath+".revoked"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEnterpriseCredential(dataDir, "uid:505", "zed", "kiro", "locked"); err != nil {
		t.Fatalf("revocation retry failed: %v", err)
	}
	for _, path := range []string{indexPath, indexPath + ".revoked"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revocation residue survived at %s: %v", path, err)
		}
	}
	if _, ok := MatchEnterpriseCredential(dataDir, credential.Token); ok {
		t.Fatal("revoked token authenticated after cleanup retry")
	}
}

func TestEnterpriseCredentialRevocationResumesRecordTombstoneCleanup(t *testing.T) {
	dataDir := t.TempDir()
	credential, err := EnsureEnterpriseCredential(dataDir, "alice", "zed", "kiro", "default")
	if err != nil {
		t.Fatal(err)
	}
	recordPath, err := EnterpriseCredentialPath(dataDir, "alice", "zed", "kiro", "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := renameEnterpriseCredentialFile(recordPath, recordPath+".revoked"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEnterpriseCredential(dataDir, "alice", "zed", "kiro", "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(recordPath + ".revoked"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record tombstone remains after resumed cleanup: %v", err)
	}
	if _, ok := MatchEnterpriseCredential(dataDir, credential.Token); ok {
		t.Fatal("interrupted record revocation left credential authoritative")
	}
}

func TestEnterpriseCredentialMissingIndexRotatesInsteadOfResurrecting(t *testing.T) {
	requireDirectEnterpriseCredentialTest(t)
	dataDir := t.TempDir()
	first, err := EnsureEnterpriseCredential(dataDir, "uid:504", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	indexPath, err := EnterpriseCredentialIndexPath(dataDir, first.Token)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate interruption immediately after revocation removes its
	// bearer-derived authority but before the service record is retired.
	if err := os.Remove(indexPath); err != nil {
		t.Fatal(err)
	}
	reissued, err := EnsureEnterpriseCredential(dataDir, "uid:504", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if reissued.Token == first.Token {
		t.Fatal("re-enrollment resurrected a credential whose index was revoked")
	}
	if _, ok := MatchEnterpriseCredential(dataDir, first.Token); ok {
		t.Fatal("interrupted revocation token regained authority")
	}
	if matched, ok := MatchEnterpriseCredential(dataDir, reissued.Token); !ok || matched != reissued {
		t.Fatalf("rotated credential did not match: %+v, %v", matched, ok)
	}
}

func TestEnterpriseCredentialRejectsRecordScopeTamper(t *testing.T) {
	requireDirectEnterpriseCredentialTest(t)
	dataDir := t.TempDir()
	credential, err := EnsureEnterpriseCredential(dataDir, "uid:502", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	path, err := EnterpriseCredentialPath(dataDir, "uid:502", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range body {
		if index+len(`"profile": "locked"`) <= len(body) && string(body[index:index+len(`"profile": "locked"`)]) == `"profile": "locked"` {
			copy(body[index:index+len(`"profile": "locked"`)], []byte(`"profile": "stolen"`))
			break
		}
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := MatchEnterpriseCredential(dataDir, credential.Token); ok {
		t.Fatal("scope-tampered record matched")
	}
}

func requireDirectEnterpriseCredentialTest(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("direct credential API requires an installer-protected service tree on Windows; covered by enterprise CLI/E2E tests")
	}
}

func TestPublishEnterpriseUserTokenUsesPerBindingPrivatePath(t *testing.T) {
	dataDir := t.TempDir()
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	path, err := PublishEnterpriseUserToken(dataDir, "zed", "kiro", token)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "acp", "zed-kiro.token")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("token mode = %o", info.Mode().Perm())
		}
	}
}
