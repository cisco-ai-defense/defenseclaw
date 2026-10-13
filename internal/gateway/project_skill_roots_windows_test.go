// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1356: the managed Windows gateway service may not stat an enrolled
// user's profile, so a project skill folder was never registered and its
// skills loaded unscanned. The first hook from a project registers its
// skill folder once the hook guardian verified it and granted the service
// read access; a folder outside the caller's own home, a link to another
// user's tree, or a caller that is not enrolled is not registered, and a
// folder that could not be verified is refused and named in the watcher
// health. Also keeps GAP-1297 (no junction escape), GAP-1349 (one
// registration, one restart signal) and GAP-1063 (refused until scanned).
func TestManagedWindowsProjectSkillRootFromFirstHook(t *testing.T) {
	restoreTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	restoreHome, restoreLstat, restoreCWD := userScopedIdentityHome, projectSkillLstat, resolveHookCWD
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreTrust
		userScopedIdentityHome, projectSkillLstat, resolveHookCWD = restoreHome, restoreLstat, restoreCWD
	})

	root := t.TempDir()
	alice, bob, carol := filepath.Join(root, "alice"), filepath.Join(root, "bob"), filepath.Join(root, "carol")
	const aliceSID, bobSID, carolSID = "S-1-5-21-1-1001", "S-1-5-21-1-1002", "S-1-5-21-1-1003"
	skill := func(skills, name string) {
		dir := filepath.Join(skills, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	projA := filepath.Join(alice, "projA")
	skillsA := filepath.Join(projA, ".claude", "skills")
	skill(skillsA, "x")
	skill(filepath.Join(bob, "projB", ".claude", "skills"), "y")
	skill(filepath.Join(carol, "projK", ".claude", "skills"), "k")
	skill(filepath.Join(root, "shared", "projO", ".claude", "skills"), "o")
	projC := filepath.Join(alice, "projC")
	if err := os.MkdirAll(projC, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(projC, ".claude"), filepath.Join(bob, "projB", ".claude")).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}

	dataDir := filepath.Join(root, "data")
	record := map[string]any{
		"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339), "ok": true,
		"target_count": 2, "success_count": 2, "failure_count": 0,
		"protected_targets": []map[string]any{
			{"user": "alice", "user_home": alice, "sid": aliceSID, "connector": "claudecode", "ok": true},
			{"user": "bob", "user_home": bob, "sid": bobSID, "connector": "claudecode", "ok": true},
		},
	}
	raw, _ := json.Marshal(record)
	authorization := managed.HookGuardianAuthorizationPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(authorization), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorization, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise, AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Enterprise.Profile = managed.ProfileStandalone

	homes := map[string]string{aliceSID: alice, bobSID: bob, carolSID: carol}
	userScopedIdentityHome = func(sid string) string { return homes[sid] }
	// The service account: a profile and what is in it are denied unless
	// the guardian granted a folder; a missing path is still missing.
	granted := map[string]bool{}
	projectSkillLstat = func(path string) (fs.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return info, err
		}
		for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
			if granted[strings.ToLower(dir)] {
				return info, nil
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
		for _, home := range homes {
			if strings.EqualFold(filepath.Clean(path), home) || insideHome(home, path) {
				return nil, &fs.PathError{Op: "lstat", Path: path, Err: windows.ERROR_ACCESS_DENIED}
			}
		}
		return info, nil
	}
	// Nor can it resolve a working directory in a profile, so the hook's
	// cwd reached the hooks empty (the root cause seen live).
	resolveHookCWD = func(cwd string) (string, error) {
		if _, err := projectSkillLstat(cwd); err != nil {
			return "", err
		}
		return restoreCWD(cwd)
	}
	grants := 0
	roots := &projectSkillRoots{}
	roots.start(true)
	// The guardian's checks (grantEnrolledAssetRead) before its grant.
	roots.setReadGranter(func(targetType, path string) error {
		grants++
		project, ok := EnrolledProjectSkillRoot(cfg, path)
		if !ok {
			return errors.New("not an enrolled project skill folder")
		}
		dir, err := enforce.VerifyProjectSkillRootReadGrant(enforce.QuarantineRemovalRequest{
			Version: 1, ID: "read-test", Kind: enforce.QuarantineRequestReadGrant, TargetType: targetType, SourcePath: path,
		}, project.Dir, project.Home)
		if err != nil {
			return err
		}
		granted[strings.ToLower(dir)] = true
		return nil
	})
	store, logger := newNativeSkillRuntimeTestStore(t)
	health := NewSidecarHealth()
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg, projectSkills: roots, health: health}
	caller := func(sid string) context.Context {
		return context.WithValue(withServiceAccountGateway(context.Background()), verifiedUserScopedIdentityContextKey{}, sid)
	}
	// Requests are decoded as the hook route decodes them.
	decode := func(ctx context.Context, event, cwd, skill string) claudeCodeHookRequest {
		body := map[string]interface{}{"hook_event_name": event, "cwd": cwd, "session_id": "s-1356"}
		if skill != "" {
			body["tool_name"], body["tool_input"] = "Skill", map[string]interface{}{"skill": skill}
		}
		raw, _ := json.Marshal(body)
		return decodeClaudeCodeRequestForContext(ctx, raw, body)
	}
	sessionStart := func(sid, cwd string) {
		ctx := caller(sid)
		api.noteProjectSkillFolders(ctx, "claudecode", decode(ctx, "SessionStart", cwd, "").CWD)
	}
	useSkill := func(sid, cwd, name string) (config.AssetPolicyDecision, bool) {
		ctx := caller(sid)
		return api.claudeCodeSkillAssetDecision(ctx, decode(ctx, "PreToolUse", cwd, name))
	}
	changed := roots.changeSignal()
	signalled := func() bool {
		select {
		case <-changed:
			return true
		default:
			return false
		}
	}

	// An unresolved home, a project outside the home and another user's
	// home register nothing and never ask the guardian.
	sessionStart("S-1-5-21-1-9999", projA)
	sessionStart(aliceSID, filepath.Join(root, "shared", "projO"))
	sessionStart(aliceSID, filepath.Join(bob, "projB"))
	if grants != 0 || signalled() || roots.registered(filepath.Join(bob, "projB", ".claude", "skills")) {
		t.Fatalf("an unresolved, outside or other-user folder was considered (grants=%d)", grants)
	}

	// A caller whose home is not an enrolled user's is refused.
	sessionStart(carolSID, filepath.Join(carol, "projK"))
	if reason, _ := roots.refusal(filepath.Join(carol, "projK", ".claude", "skills"), time.Now()); reason == "" || grants != 0 {
		t.Fatalf("unlisted home: reason=%q grants=%d", reason, grants)
	}

	// A junction to another user's project is refused by the guardian and
	// not watched; its skill is refused and the watcher health names it.
	decision, matched := useSkill(aliceSID, projC, "y")
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Fatalf("skill behind a junction = %+v, matched=%v; want refused as unverified", decision, matched)
	}
	if roots.registered(filepath.Join(projC, ".claude", "skills")) || grants != 1 {
		t.Fatalf("junction registered or not checked once (grants=%d)", grants)
	}
	listed := roots.unverifiedFolders()
	if count, _ := health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail].(int); count != 2 ||
		!strings.Contains(strings.Join(listed, "\n"), projC) {
		t.Fatalf("watcher health unverified folders = %d, %v", count, listed)
	}

	// The project under the home, reported in another case: registered on
	// the first hook, the new skill refused until admission records it.
	upper := strings.ToUpper(projA)
	if decision, matched := useSkill(aliceSID, upper, "x"); !matched || decision.Action != "block" || decision.Source != "project-skill-pending" {
		t.Fatalf("unadmitted project skill = %+v, matched=%v; want refused as pending", decision, matched)
	}
	if !roots.registered(skillsA) || grants != 2 || !signalled() {
		t.Fatalf("project folder registered=%v grants=%d", roots.registered(skillsA), grants)
	}
	for i := 0; i < 3; i++ {
		sessionStart(aliceSID, projA)
	}
	if grants != 2 || signalled() {
		t.Fatalf("repeated hooks asked the guardian again or signalled a restart (grants=%d)", grants)
	}
	registeredAs, _ := roots.registeredPath(skillsA)
	if err := store.SetTargetSnapshot("skill", filepath.Join(registeredAs, "x"), "h", "{}", "{}", "[]", "scan-1", "fp"); err != nil {
		t.Fatal(err)
	}
	if decision, matched := useSkill(aliceSID, projA, "x"); matched {
		t.Fatalf("admitted project skill = %+v, want it judged as usual", decision)
	}
}
