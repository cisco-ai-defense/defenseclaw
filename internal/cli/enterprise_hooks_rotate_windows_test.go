// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func TestWindowsManagedRotationPrepareCommitRollback(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice", "bob")
	req := env.request()

	prepared, err := executeWindowsManagedRotationPrepare(req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.Phase != enterpriseHookRotationPhasePrepared {
		t.Fatalf("prepare phase = %q", prepared.Phase)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenB {
		t.Fatal("alice did not receive generation B")
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenB {
		t.Fatal("bob did not receive generation B")
	}
	authorization, exists, err := loadEnterpriseHookGuardianAuthorization(env.serviceDir)
	if err != nil || !exists || authorization.Current == nil || !authorization.Current.OK {
		t.Fatalf("current readiness after prepare: exists=%v err=%v current=%v", exists, err, authorization.Current)
	}
	if authorization.Current.Generation != env.generation {
		t.Fatalf("current generation = %q, want rotation generation", authorization.Current.Generation)
	}
	if _, err := os.Lstat(enterpriseHookRotationJournalPath(env.serviceDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("POSIX guardian journal was written on Windows")
	}
	if windowsJournalHasSecret(t, env.serviceDir, env.tokenA, env.tokenB) {
		t.Fatal("public Windows journal contained raw token material")
	}

	again, err := executeWindowsManagedRotationPrepare(req)
	if err != nil {
		t.Fatalf("idempotent prepare: %v", err)
	}
	if again.Phase != enterpriseHookRotationPhasePrepared {
		t.Fatalf("idempotent prepare phase = %q", again.Phase)
	}

	committed, err := executeWindowsManagedRotationCommit(req)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if committed.Phase != enterpriseHookRotationPhaseCommitted {
		t.Fatalf("commit phase = %q", committed.Phase)
	}
	if _, err := os.Lstat(windowsManagedRotationRollbackPath(env.serviceDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback material survived commit: %v", err)
	}
	if _, err := executeWindowsManagedRotationCommit(req); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
}

func TestWindowsManagedRotationPreparingJournalRefusesResumeThenRollbackRestoresA(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice", "bob")
	targets := []enterpriseHookRotationTarget{env.rotationTarget("alice"), env.rotationTarget("bob")}
	if err := writeWindowsManagedRotationJournal(env.serviceDir, windowsManagedRotationJournal{
		Schema:         windowsManagedRotationSchema,
		Version:        enterpriseHookRotationJournalVersion,
		OperationID:    env.operation,
		Generation:     env.generation,
		Manifest:       env.manifest,
		ManifestSHA256: testEnterpriseHookManifestSHA256,
		Phase:          enterpriseHookRotationPhasePreparing,
		Targets:        targets,
		UpdatedAt:      "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed preparing journal: %v", err)
	}
	alice := targets[0]
	if err := snapshotWindowsManagedRotationTarget(env.serviceDir, alice); err != nil {
		t.Fatalf("snapshot A for alice: %v", err)
	}
	snapshotPath := windowsManagedRotationSnapshotPath(env.serviceDir, alice)
	beforeSnapshot := mustRead(t, snapshotPath)
	if err := connector.PublishHookAPIToken(filepath.Join(env.homes["alice"], ".defenseclaw"), env.connectors["alice"], env.tokenB); err != nil {
		t.Fatalf("publish B for alice: %v", err)
	}

	prepared, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !strings.Contains(err.Error(), "operation is already preparing; rollback first") {
		t.Fatalf("prepare error = %v, want preparing-journal refusal", err)
	}
	if prepared.Phase != enterpriseHookRotationPhasePreparing {
		t.Fatalf("refused prepare phase = %q", prepared.Phase)
	}
	if afterSnapshot := mustRead(t, snapshotPath); afterSnapshot != beforeSnapshot {
		t.Fatal("prepare overwrote the generation A snapshot")
	}
	record, err := loadWindowsManagedRotationRecord(snapshotPath)
	if err != nil {
		t.Fatalf("reload A snapshot: %v", err)
	}
	if record.Artifact.Digest != managed.ScopedTokenFingerprint(env.tokenA) {
		t.Fatal("prepare replaced the generation A snapshot digest")
	}

	rolled, err := executeWindowsManagedRotationRollback(env.request())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.Phase != enterpriseHookRotationPhaseRolledBack {
		t.Fatalf("rollback phase = %q", rolled.Phase)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("alice was not restored to generation A")
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenA {
		t.Fatal("bob was not left on generation A")
	}
}

func TestWindowsManagedRotationPartialPrepareRestoresA(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice", "bob")
	writes := 0
	originalAfter := windowsManagedRotationAfterTargetWrite
	t.Cleanup(func() { windowsManagedRotationAfterTargetWrite = originalAfter })
	windowsManagedRotationAfterTargetWrite = func(target enterpriseHookRotationTarget) error {
		writes++
		if writes == 2 {
			return errors.New("injected post-write failure")
		}
		return nil
	}

	_, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil {
		t.Fatal("prepare error = nil, want injected failure")
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("alice was not restored to generation A")
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenA {
		t.Fatal("bob was not restored to generation A")
	}
}

func TestWindowsManagedRotationRestoreRefusesTargetMismatch(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice", "bob")
	alice := env.rotationTarget("alice")
	bob := env.rotationTarget("bob")
	if err := snapshotWindowsManagedRotationTarget(env.serviceDir, alice); err != nil {
		t.Fatalf("snapshot alice: %v", err)
	}
	record, err := loadWindowsManagedRotationRecord(windowsManagedRotationSnapshotPath(env.serviceDir, alice))
	if err != nil {
		t.Fatalf("load alice snapshot: %v", err)
	}
	if err := encodeWindowsManagedRotationSnapshot(windowsManagedRotationSnapshotPath(env.serviceDir, bob), record.Target, record.Artifact); err != nil {
		t.Fatalf("plant mismatched snapshot: %v", err)
	}
	if err := restoreWindowsManagedRotationTarget(env.serviceDir, bob); err == nil || !strings.Contains(err.Error(), "target does not match") {
		t.Fatalf("restore error = %v, want target mismatch", err)
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenA {
		t.Fatal("bob was mutated after mismatched restore")
	}
}

func TestWindowsManagedRotationRestoreSkipsMissingSnapshots(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice", "bob")
	alice := enterpriseHookRotationTarget{
		User:      "alice",
		UserHome:  env.homes["alice"],
		SID:       env.sid,
		Connector: env.connectors["alice"],
	}
	bob := enterpriseHookRotationTarget{
		User:      "bob",
		UserHome:  env.homes["bob"],
		SID:       env.sid,
		Connector: env.connectors["bob"],
	}
	if err := snapshotWindowsManagedRotationTarget(env.serviceDir, alice); err != nil {
		t.Fatalf("snapshot alice: %v", err)
	}
	if err := restoreWindowsManagedRotationMutated(env.serviceDir, []enterpriseHookRotationTarget{alice, bob}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := env.publishedToken(t, "bob"); got != env.tokenA {
		t.Fatal("unsnapshotted bob was mutated")
	}
}

func TestWindowsManagedRotationRollbackRestoresExactA(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice")
	if _, err := executeWindowsManagedRotationPrepare(env.request()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	rolled, err := executeWindowsManagedRotationRollback(env.request())
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.Phase != enterpriseHookRotationPhaseRolledBack {
		t.Fatalf("rollback phase = %q", rolled.Phase)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("alice was not restored to generation A")
	}
}

func TestWindowsManagedRotationRefusesPOSIXJournal(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice")
	if err := os.MkdirAll(filepath.Dir(enterpriseHookRotationJournalPath(env.serviceDir)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enterpriseHookRotationJournalPath(env.serviceDir), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !strings.Contains(err.Error(), "POSIX guardian journal is forbidden") {
		t.Fatalf("prepare error = %v, want POSIX journal refusal", err)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("token A was mutated after POSIX journal refusal")
	}
}

func TestWindowsManagedRotationRefusesCursor(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice")
	env.replaceConnector(t, "cursor")
	_, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !strings.Contains(err.Error(), "certified Claude/Codex") {
		t.Fatalf("prepare error = %v, want cursor refusal", err)
	}
}

func TestWindowsManagedRotationRefusesMissingSession(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice")
	original := windowsManagedRotationSessionCheck
	t.Cleanup(func() { windowsManagedRotationSessionCheck = original })
	windowsManagedRotationSessionCheck = func(sid, _ string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: sid}
	}
	_, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !strings.Contains(err.Error(), "no active interactive session") {
		t.Fatalf("prepare error = %v, want missing-session refusal", err)
	}
	if got := env.publishedToken(t, "alice"); got != env.tokenA {
		t.Fatal("token A was mutated without an interactive session")
	}
}

func TestWindowsManagedRotationRefusesMissingSID(t *testing.T) {
	env := newWindowsManagedRotationTestEnv(t, "alice")
	env.clearSID(t)
	_, err := executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !(strings.Contains(err.Error(), "manifest-pinned SID") || strings.Contains(err.Error(), "requires explicit sid")) {
		t.Fatalf("prepare error = %v, want missing SID refusal", err)
	}
}

func TestWindowsManagedRotationRequiresLocalSystem(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("runner is LocalSystem")
	}
	env := newWindowsManagedRotationTestEnv(t, "alice")
	enterpriseHooksMutationIdentityPreflight = enterpriseHooksNativeMutationIdentityPreflight
	_, err = executeWindowsManagedRotationPrepare(env.request())
	if err == nil || !strings.Contains(err.Error(), "LocalSystem") {
		t.Fatalf("prepare error = %v, want LocalSystem refusal", err)
	}
}

func TestWindowsManagedRotationInspectRejectsHardLink(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "token")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(primary, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(primary, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	_, err := inspectWindowsManagedRotationPath(primary)
	if err == nil || !strings.Contains(err.Error(), "single-link") {
		t.Fatalf("inspect error = %v, want single-link refusal", err)
	}
}

func TestWindowsManagedRotationInspectRejectsReparse(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := inspectWindowsManagedRotationPath(link)
	if err == nil || !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("inspect error = %v, want reparse refusal", err)
	}
}

func TestWindowsManagedRotationPOSIXExecuteStillRefused(t *testing.T) {
	_, err := executeEnterpriseHookRotationPrepare(enterpriseHookRotationRequest{
		OperationID:  strings.Repeat("1", 32),
		Generation:   strings.Repeat("2", 32),
		Manifest:     `C:\ProgramData\DefenseClaw\targets.yaml`,
		Fingerprints: `C:\ProgramData\DefenseClaw\expected-fingerprints.json`,
	})
	if err == nil || !strings.Contains(err.Error(), "native guardian adapter") {
		t.Fatalf("posix prepare error = %v, want native adapter refusal", err)
	}
}

type windowsManagedRotationTestEnv struct {
	scope      string
	serviceDir string
	homes      map[string]string
	connectors map[string]string
	sid        string
	tokenA     string
	tokenB     string
	operation  string
	generation string
	manifest   string
	prints     string
}

func newWindowsManagedRotationTestEnv(t *testing.T, users ...string) *windowsManagedRotationTestEnv {
	t.Helper()
	scope := t.TempDir()
	serviceDir := filepath.Join(scope, "service")
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sid := currentWindowsTestSID(t)
	env := &windowsManagedRotationTestEnv{
		scope:      scope,
		serviceDir: serviceDir,
		homes:      map[string]string{},
		connectors: map[string]string{},
		sid:        sid,
		tokenA:     strings.Repeat("a", 64),
		tokenB:     strings.Repeat("b", 64),
		operation:  strings.Repeat("1", 32),
		generation: strings.Repeat("2", 32),
	}

	originalCfg := cfg
	originalTrust := enterpriseHookManifestFileTrustCheck
	originalDirTrust := enterpriseHookAuthorizationDirTrustCheck
	originalFileTrust := enterpriseHookAuthorizationFileTrustCheck
	originalOwner := enterpriseHookAuthorizationOwnershipSetter
	originalStateTrust := enterpriseHookGuardianStateFileTrustCheck
	originalMutation := enterpriseHooksMutationIdentityPreflight
	originalLoadB := windowsManagedRotationLoadB
	originalSpace := windowsManagedRotationSpaceCheck
	originalSession := windowsManagedRotationSessionCheck
	originalImpersonate := windowsManagedRotationImpersonate
	t.Cleanup(func() {
		cfg = originalCfg
		enterpriseHookManifestFileTrustCheck = originalTrust
		enterpriseHookAuthorizationDirTrustCheck = originalDirTrust
		enterpriseHookAuthorizationFileTrustCheck = originalFileTrust
		enterpriseHookAuthorizationOwnershipSetter = originalOwner
		enterpriseHookGuardianStateFileTrustCheck = originalStateTrust
		enterpriseHooksMutationIdentityPreflight = originalMutation
		windowsManagedRotationLoadB = originalLoadB
		windowsManagedRotationSpaceCheck = originalSpace
		windowsManagedRotationSessionCheck = originalSession
		windowsManagedRotationImpersonate = originalImpersonate
	})
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHooksMutationIdentityPreflight = func() error { return nil }
	windowsManagedRotationSpaceCheck = func(string) error { return nil }
	windowsManagedRotationLoadB = func(string, string) (string, error) { return env.tokenB, nil }
	windowsManagedRotationSessionCheck = func(string, string) error { return nil }
	windowsManagedRotationImpersonate = func(_ *windows.SID, _ string, fn func() error) error { return fn() }

	var manifest strings.Builder
	manifest.WriteString("version: 1\ntargets:\n")
	rows := make([]enterpriseHookReconcileRow, 0, len(users))
	expected := enterpriseHookRotationFingerprintFile{Targets: make([]enterpriseHookRotationTarget, 0, len(users))}
	for index, user := range users {
		home := filepath.Join(scope, "home", user)
		dataDir := filepath.Join(home, ".defenseclaw")
		if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
			t.Fatal(err)
		}
		connectorName := "codex"
		agentVersion := "1.7.0"
		if index > 0 {
			connectorName = "claudecode"
			agentVersion = "2.1.240"
		}
		if err := connector.PublishHookAPIToken(dataDir, connectorName, env.tokenA); err != nil {
			t.Fatalf("publish A for %s: %v", user, err)
		}
		env.homes[user] = home
		env.connectors[user] = connectorName
		manifest.WriteString("  - user: " + user + "\n    user_home: " + home + "\n    sid: " + sid + "\n    connector: " + connectorName + "\n    agent_version: " + agentVersion + "\n")
		rows = append(rows, enterpriseHookReconcileRow{
			User:             user,
			UserHome:         home,
			SID:              sid,
			Connector:        connectorName,
			OK:               true,
			TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenA),
		})
		expected.Targets = append(expected.Targets, enterpriseHookRotationTarget{
			User:             user,
			UserHome:         home,
			SID:              sid,
			Connector:        connectorName,
			TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenB),
		})
	}
	env.manifest = filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(env.manifest, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	prints, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	env.prints = filepath.Join(scope, "expected-fingerprints.json")
	if err := os.WriteFile(env.prints, prints, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	cfg = &config.Config{DataDir: serviceDir}
	if err := writeEnterpriseHookGuardianState(serviceDir, env.manifest, testEnterpriseHookManifestSHA256, rows, 0, true); err != nil {
		t.Fatalf("seed current attestations: %v", err)
	}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	return env
}

func (env *windowsManagedRotationTestEnv) rotationTarget(user string) enterpriseHookRotationTarget {
	return enterpriseHookRotationTarget{
		User:             user,
		UserHome:         env.homes[user],
		SID:              env.sid,
		Connector:        env.connectors[user],
		TokenFingerprint: managed.ScopedTokenFingerprint(env.tokenB),
	}
}

func (env *windowsManagedRotationTestEnv) request() enterpriseHookRotationRequest {
	return enterpriseHookRotationRequest{
		OperationID:  env.operation,
		Generation:   env.generation,
		Manifest:     env.manifest,
		Fingerprints: env.prints,
	}
}

func (env *windowsManagedRotationTestEnv) publishedToken(t *testing.T, user string) string {
	t.Helper()
	token, err := connector.LoadHookAPIToken(filepath.Join(env.homes[user], ".defenseclaw"), env.connectors[user])
	if err != nil {
		t.Fatalf("load published token for %s: %v", user, err)
	}
	return token
}

func (env *windowsManagedRotationTestEnv) replaceConnector(t *testing.T, connectorName string) {
	t.Helper()
	body, err := os.ReadFile(env.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.manifest, []byte(strings.ReplaceAll(string(body), "codex", connectorName)), 0o600); err != nil {
		t.Fatal(err)
	}
	prints, err := os.ReadFile(env.prints)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.prints, []byte(strings.ReplaceAll(string(prints), "codex", connectorName)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (env *windowsManagedRotationTestEnv) clearSID(t *testing.T) {
	t.Helper()
	body, err := os.ReadFile(env.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.ReplaceAll(string(body), "    sid: "+env.sid+"\n", "")
	if err := os.WriteFile(env.manifest, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	var file enterpriseHookRotationFingerprintFile
	if err := json.Unmarshal([]byte(mustRead(t, env.prints)), &file); err != nil {
		t.Fatal(err)
	}
	for i := range file.Targets {
		file.Targets[i].SID = ""
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.prints, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func currentWindowsTestSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current test SID: %v", err)
	}
	return user.User.Sid.String()
}

func windowsJournalHasSecret(t *testing.T, dataDir string, secrets ...string) bool {
	t.Helper()
	path := windowsManagedRotationJournalPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Windows journal: %v", err)
	}
	text := string(data)
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			return true
		}
	}
	return false
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
