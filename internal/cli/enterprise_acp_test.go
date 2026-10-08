// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

	"github.com/spf13/cobra"
)

func TestEnterpriseACPEnrollVerifyRevokeLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows lifecycle is covered by exact-SID integration tests")
	}
	serviceData := t.TempDir()
	userHome := t.TempDir()
	userData := filepath.Join(userHome, "custom-acp-data")
	previousCfg := cfg
	previous := struct {
		client, agent, profile, user, home, sid, data string
		uid, gid                                      int
		json                                          bool
	}{
		enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile,
		enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID,
		enterpriseACPUserDataDir, enterpriseACPUID, enterpriseACPGID, enterpriseACPJSON,
	}
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = previous.client, previous.agent, previous.profile
		enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID = previous.user, previous.home, previous.sid
		enterpriseACPUserDataDir, enterpriseACPUID, enterpriseACPGID = previous.data, previous.uid, previous.gid
		enterpriseACPJSON = previous.json
	})
	cfg = &config.Config{
		DataDir: serviceData, DeploymentMode: "managed_enterprise",
		ACP: config.ACPConfig{
			Enabled: true, Mode: "action", DefaultProfile: "locked",
			Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "locked"}},
			Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]config.ACPProfile{"locked": {
				AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
			}},
		},
	}
	enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = "zed", "kiro", "locked"
	enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID = "", userHome, ""
	enterpriseACPUserDataDir, enterpriseACPUID, enterpriseACPGID = userData, -1, -1
	enterpriseACPJSON = true

	// A SID names no account a Unix gateway can bind (GAP-0200).
	cfg.Enterprise.Profile = "standalone"
	enterpriseACPSID = "S-1-5-21-1-2-3-500"
	if _, err := resolveEnterpriseACPEnrollment(true); err == nil {
		t.Fatal("a Windows SID was accepted as a standalone Unix enrollment principal")
	}
	enterpriseACPSID = ""

	run := func(fn func(*cobra.Command, []string) error) map[string]any {
		t.Helper()
		var output bytes.Buffer
		command := &cobra.Command{}
		command.SetOut(&output)
		if err := fn(command, nil); err != nil {
			t.Fatalf("operation failed: %v; output=%s", err, output.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
			t.Fatalf("decode output: %v; output=%s", err, output.String())
		}
		return payload
	}

	// An account with no home is refused in words, not with an lstat error
	// (GAP-0687).
	enterpriseACPJSON = false
	enterpriseACPUserHome, enterpriseACPUserDataDir = filepath.Join(userHome, "missing"), filepath.Join(userHome, "missing", ".defenseclaw")
	if err := runEnterpriseACPEnroll(&cobra.Command{}, nil); err == nil ||
		!strings.Contains(err.Error(), "has no home directory") || strings.Contains(err.Error(), "lstat") {
		t.Fatalf("enroll of an account without a home: %v", err)
	}
	// With --json the cause is on stdout once; stderr adds nothing (GAP-0688).
	enterpriseACPJSON = true
	var jsonOut bytes.Buffer
	jsonCommand := &cobra.Command{}
	jsonCommand.SetOut(&jsonOut)
	if err := runEnterpriseACPEnroll(jsonCommand, nil); err == nil || !jsonCommand.SilenceErrors ||
		!strings.Contains(jsonOut.String(), "has no home directory") {
		t.Fatalf("--json refusal: err=%v silenced=%v stdout=%s", err, jsonCommand.SilenceErrors, jsonOut.String())
	}
	enterpriseACPUserHome, enterpriseACPUserDataDir = userHome, userData

	// An enrollment that cannot publish the bearer leaves no credential,
	// and a failed re-enrollment keeps the working one (GAP-0260).
	failEnroll := func(why string) {
		t.Helper()
		var output bytes.Buffer
		command := &cobra.Command{}
		command.SetOut(&output)
		if err := runEnterpriseACPEnroll(command, nil); err == nil {
			t.Fatalf("enroll succeeded although %s: %s", why, output.String())
		}
	}
	if err := os.WriteFile(userData, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failEnroll("the user data dir is a file")
	pending, err := resolveEnterpriseACPEnrollment(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acp.LoadEnterpriseCredential(serviceData, pending.principal, "zed", "kiro", "locked"); !os.IsNotExist(err) {
		t.Fatalf("a failed enrollment left its minted credential: %v", err)
	}
	if err := os.Remove(userData); err != nil {
		t.Fatal(err)
	}

	enrolled := run(runEnterpriseACPEnroll)
	if next, _ := enrolled["next"].(string); !strings.Contains(next, " --activate") ||
		!strings.Contains(next, " enterprise acp setup --client zed --agent kiro --profile locked") {
		// The reported command must exist on a managed host, which has only the
		// gateway binary (GAP-0254).
		t.Fatalf("setup command lost the inherited action mode or names a command a managed host lacks: %q", next)
	}
	tokenPath, _ := enrolled["token_file"].(string)
	if tokenPath != filepath.Join(userData, "acp", "zed-kiro.token") {
		t.Fatalf("token path = %q", tokenPath)
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatal(err)
	}
	// A second administrator cannot start an enrollment transaction while
	// the first still owns the service credential and its publication step.
	var release func()
	if err := withEnterpriseACPServiceOwner(serviceData, func() error {
		var lockErr error
		release, lockErr = acp.AcquireEnterpriseCredentialEnrollmentLock(serviceData)
		return lockErr
	}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		var output bytes.Buffer
		command := &cobra.Command{}
		command.SetOut(&output)
		finished <- runEnterpriseACPEnroll(command, nil)
	}()
	select {
	case err := <-finished:
		release()
		t.Fatalf("concurrent enrollment passed the active transaction: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	release()
	if err := <-finished; err != nil {
		t.Fatalf("enrollment after transaction release: %v", err)
	}
	// Revoke must wait until an enrollment has finished publishing its
	// user token, then leave the next enrollment free to publish again.
	if err := withEnterpriseACPServiceOwner(serviceData, func() error {
		var lockErr error
		release, lockErr = acp.AcquireEnterpriseCredentialEnrollmentLock(serviceData)
		return lockErr
	}); err != nil {
		t.Fatal(err)
	}
	go func() {
		command := &cobra.Command{}
		command.SetOut(&bytes.Buffer{})
		finished <- runEnterpriseACPRevoke(command, nil)
	}()
	select {
	case err := <-finished:
		release()
		t.Fatalf("concurrent revoke passed the active enrollment transaction: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	release()
	if err := <-finished; err != nil {
		t.Fatalf("revoke after transaction release: %v", err)
	}
	run(runEnterpriseACPEnroll)
	// verify tells a published token from a completed setup, and list
	// names who is enrolled and how far they got (GAP-0400).
	if verified := run(runEnterpriseACPVerify); verified["setup_done"] != false {
		t.Fatalf("verify did not report that setup has not run: %v", verified)
	}
	// A lock whose editor entry was set up in another home (an account
	// rename moved the home) is not a done setup (GAP-0693).
	staleLock := acpContractLockPath(userData, "zed", "kiro")
	if err := os.MkdirAll(filepath.Dir(staleLock), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleLock, []byte(`{"version":1,"client":{"id":"zed","config_path":"/home/renamed-away/.config/zed/settings.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if verified := run(runEnterpriseACPVerify); verified["setup_done"] != false ||
		!strings.Contains(fmt.Sprint(verified["setup_note"]), "outside the home") {
		t.Fatalf("verify called a stale editor entry set up: %v", verified)
	}
	if err := os.Remove(staleLock); err != nil {
		t.Fatal(err)
	}
	restoreDescribe := enterpriseACPDescribePrincipal
	t.Cleanup(func() { enterpriseACPDescribePrincipal = restoreDescribe })
	enterpriseACPDescribePrincipal = func(string) (enterpriseACPAccount, error) {
		return enterpriseACPAccount{exists: true, name: "alice", home: userHome, uid: -1, gid: -1}, nil
	}
	listed, _ := run(runEnterpriseACPList)["enrollments"].([]any)
	if len(listed) != 1 {
		t.Fatalf("list = %v, want the one enrollment", listed)
	}
	if row, _ := listed[0].(map[string]any); row["user"] != "alice" || row["client"] != "zed" || row["agent"] != "kiro" ||
		row["token_copy"] != "present" || row["setup"] != "not run" {
		t.Fatalf("list row = %v, want alice zed/kiro with the token copy present and setup not run", row)
	}
	// A done setup: the lock pins an editor file in the home whose managed
	// entry points at this data directory's token copy and lock.
	doneLock := acpContractLockPath(userData, "zed", "kiro")
	editorFile := filepath.Join(userHome, ".config", "zed", "settings.json")
	if err := os.MkdirAll(filepath.Dir(editorFile), 0o700); err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(map[string]any{"agent_servers": map[string]any{
		acpManagedEntryName("kiro"): map[string]any{"args": []string{"--token-file", tokenPath, "--contract-lock", doneLock}},
	}})
	if err := os.WriteFile(editorFile, entry, 0o600); err != nil {
		t.Fatal(err)
	}
	writeLock := func(profile, mode string) {
		t.Helper()
		lock, _ := json.Marshal(map[string]any{"version": 1, "client": map[string]any{"id": "zed", "config_path": editorFile},
			"profile": profile, "mode": mode})
		if err := os.WriteFile(doneLock, lock, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A lock of a replaced enrollment's profile, or of the other mode, is
	// not a done setup (GAP-0833).
	for _, stale := range [][2]string{{"replaced", "action"}, {"locked", "observe"}} {
		writeLock(stale[0], stale[1])
		listed, _ = run(runEnterpriseACPList)["enrollments"].([]any)
		if row, _ := listed[0].(map[string]any); row["setup"] != "stale" {
			t.Fatalf("list row = %v for a lock of %v, want setup stale", row, stale)
		}
	}
	writeLock("locked", "action")
	listed, _ = run(runEnterpriseACPList)["enrollments"].([]any)
	if row, _ := listed[0].(map[string]any); row["token_copy"] != "present" || row["setup"] != "done" {
		t.Fatalf("list row = %v, want the custom directory token and setup lock", row)
	}
	// A pair the central policy moved to another profile is flagged with
	// the profile to enroll under (GAP-0911).
	cfg.ACP.Clients["zed"], cfg.ACP.Agents["kiro"] = config.ACPBinding{Enabled: true, Profile: "moved"}, config.ACPBinding{Enabled: true, Profile: "moved"}
	listed, _ = run(runEnterpriseACPList)["enrollments"].([]any)
	verified := run(runEnterpriseACPVerify)
	if row, _ := listed[0].(map[string]any); !strings.Contains(fmt.Sprint(row["note"]), "now binds zed/kiro to profile moved") ||
		!strings.Contains(fmt.Sprint(verified["central_note"]), "enroll the user again with --profile moved") {
		t.Fatalf("a moved pair is not flagged: list %v, verify %v", row, verified)
	}
	cfg.ACP.Clients["zed"], cfg.ACP.Agents["kiro"] = config.ACPBinding{Enabled: true, Profile: "locked"}, config.ACPBinding{Enabled: true, Profile: "locked"}
	// After an account rename the recorded data directory names the old
	// home; list reads the default one of the new home (GAP-0869).
	renamedHome := t.TempDir()
	enterpriseACPDescribePrincipal = func(string) (enterpriseACPAccount, error) {
		return enterpriseACPAccount{exists: true, name: "alice2", home: renamedHome, uid: -1, gid: -1}, nil
	}
	if _, err := acp.PublishEnterpriseUserToken(filepath.Join(renamedHome, ".defenseclaw"), "zed", "kiro", strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	listed, _ = run(runEnterpriseACPList)["enrollments"].([]any)
	if row, _ := listed[0].(map[string]any); row["token_copy"] != "present" || row["setup"] != "not run" ||
		!strings.Contains(fmt.Sprint(row["note"]), "outside the home") {
		t.Fatalf("list row after a rename = %v, want the copy found in the new home and a note", row)
	}
	enterpriseACPDescribePrincipal = func(string) (enterpriseACPAccount, error) {
		return enterpriseACPAccount{exists: true, name: "alice", home: userHome, uid: -1, gid: -1}, nil
	}

	enrollment, err := resolveEnterpriseACPEnrollment(true)
	if err != nil {
		t.Fatal(err)
	}
	// Secure Client has no setup subcommand and reports the step of main
	// (GAP-0302, issue #1092).
	cfg.Enterprise.Profile = ""
	want := fmt.Sprintf("defenseclaw acp setup --managed --client zed --agent kiro --profile locked --activate --runtime-data-dir %q --token-file %q --guard-binary ", userData, tokenPath)
	if next := enterpriseACPSetupCommand(enrollment, tokenPath); !strings.HasPrefix(next, want) {
		t.Fatalf("Secure Client setup command = %q, want the one of main (%q...)", next, want)
	}
	cfg.Enterprise.Profile = "standalone"
	credential, err := acp.LoadEnterpriseCredential(serviceData, enrollment.principal, "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := acp.MatchEnterpriseCredential(serviceData, credential.Token); !ok {
		t.Fatal("enrolled token did not authenticate")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	failEnroll("the user token path is a directory")
	if _, ok := acp.MatchEnterpriseCredential(serviceData, credential.Token); !ok {
		t.Fatal("a failed re-enrollment removed the working credential")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	run(runEnterpriseACPEnroll)
	// Revocation is an incident-response operation and must remain available
	// after central policy has already been disabled.
	cfg.ACP.Enabled = false
	run(runEnterpriseACPRevoke)
	if _, ok := acp.MatchEnterpriseCredential(serviceData, credential.Token); ok {
		t.Fatal("revoked token still authenticated")
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("user token survived revoke: %v", err)
	}
	// verify and revoke of an enrollment that does not exist say so, not a
	// record path in an lstat error or "revoked" (GAP-0355).
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	if err := runEnterpriseACPVerify(command, nil); err == nil || !strings.Contains(output.String(), "no ACP enrollment for") ||
		strings.Contains(output.String(), "lstat") {
		t.Fatalf("verify of a missing enrollment: err=%v output=%s", err, output.String())
	}
	if again := run(runEnterpriseACPRevoke); again["found"] != false || again["centrally_revoked"] != false {
		t.Fatalf("revoke of a missing enrollment reported a revocation: %v", again)
	}
	// A user copy that cannot be checked does not turn "nothing was revoked"
	// into "the service record was removed" (GAP-0355).
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if again := run(runEnterpriseACPRevoke); again["found"] != false || again["ok"] != true ||
		!strings.Contains(fmt.Sprint(again["note"]), "not checked") {
		t.Fatalf("revoke of a missing enrollment with an unreadable user copy: %v", again)
	}
}

// Enrolling the same account, editor and agent under another profile
// replaces the earlier credential: both stayed live and the shared user copy
// held whichever was enrolled last (GAP-0733).
func TestEnterpriseACPEnrollReplacesTheOtherProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enrolls the current Unix user")
	}
	previousCfg := cfg
	previous := []string{enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile, enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID, enterpriseACPUserDataDir}
	previousJSON, previousUID, previousGID := enterpriseACPJSON, enterpriseACPUID, enterpriseACPGID
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = previous[0], previous[1], previous[2]
		enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID, enterpriseACPUserDataDir = previous[3], previous[4], previous[5], previous[6]
		enterpriseACPJSON, enterpriseACPUID, enterpriseACPGID = previousJSON, previousUID, previousGID
	})
	profiles := map[string]config.ACPProfile{
		"obs": {Mode: "observe", AllowedClients: []string{"zed"}, AllowedAgents: []string{"hermes"}},
		"act": {Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"hermes"}},
	}
	pin := func(profile string) {
		cfg.ACP.Clients = map[string]config.ACPBinding{"zed": {Enabled: true, Profile: profile}}
		cfg.ACP.Agents = map[string]config.ACPBinding{"hermes": {Enabled: true, Profile: profile}}
		cfg.ACP.DefaultProfile, enterpriseACPProfile = profile, profile
	}
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise", ACP: config.ACPConfig{Enabled: true, Profiles: profiles}}
	cfg.Enterprise.Profile = "standalone"
	userHome := t.TempDir()
	enterpriseACPClient, enterpriseACPAgent = "zed", "hermes"
	enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID, enterpriseACPUserDataDir = "", userHome, "", ""
	enterpriseACPJSON, enterpriseACPUID, enterpriseACPGID = true, -1, -1
	enroll := func() map[string]any {
		t.Helper()
		var output bytes.Buffer
		command := &cobra.Command{}
		command.SetOut(&output)
		if err := runEnterpriseACPEnroll(command, nil); err != nil {
			t.Fatalf("enroll: %v; %s", err, output.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	pin("obs")
	enroll()
	pin("act")
	if replaced := fmt.Sprint(enroll()["replaced"]); replaced != "[obs]" {
		t.Fatalf("replaced = %s, want [obs]", replaced)
	}
	enrollments, _, err := acp.ListEnterpriseEnrollments(cfg.DataDir)
	if err != nil || len(enrollments) != 1 || enrollments[0].Profile != "act" {
		t.Fatalf("enrollments = %+v, err = %v; want only the act enrollment", enrollments, err)
	}
	// Setup learns of the replacement from the note beside the copy
	// (GAP-0733).
	tokenPath, _ := acp.EnterpriseUserTokenPath(filepath.Join(userHome, ".defenseclaw"), "zed", "hermes")
	if note, ok := readEnterpriseACPUserEnrollment(tokenPath); !ok || note.Profile != "act" || note.Mode != "action" {
		t.Fatalf("enrollment note = %+v, %v; want profile act in action mode", note, ok)
	}
	// The user copy belongs to act after the replacement. A stale or
	// mistyped profile revoke must not remove it.
	for _, stale := range []string{"obs", "missing"} {
		t.Run(stale, func(t *testing.T) {
			pin("act")
			tokenPath, _ := enroll()["token_file"].(string)
			enterpriseACPProfile = stale
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			if err := runEnterpriseACPRevoke(command, nil); err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["found"] != false {
				t.Fatalf("missing profile %s reported found: %v", stale, payload)
			}
			if _, err := os.Stat(tokenPath); err != nil {
				t.Fatalf("active profile token after revoking %s: %v", stale, err)
			}
		})
	}
}

// The Windows refusals named hook mutation and gave no next step; they now
// name the ACP enrollment, LocalSystem and --user/--sid (GAP-0261).
func TestEnterpriseACPWindowsRefusalsSayHowToEnroll(t *testing.T) {
	cause := errors.New("enterprise hooks: per-user Windows hook mutation requires the LocalSystem guardian service")
	for name, got := range map[string]error{
		"elevated prompt": enterpriseACPWindowsTargetError(cause, true),
		"no session":      enterpriseACPWindowsTargetError(&enterprisehooks.WindowsTargetSessionUnavailableError{SID: "S-1-5-21-1-2-3-1001"}, false),
		"system owner":    enterpriseACPWindowsTargetError(errors.New("enterprise hooks: refusing non-interactive target SID S-1-5-18"), false),
	} {
		message := got.Error()
		if !strings.HasPrefix(message, "enterprise acp: ") || strings.Contains(message, "hook mutation") ||
			strings.Contains(message, "enterprise hooks") {
			t.Errorf("%s: the refusal does not name the ACP enrollment: %q", name, message)
		}
		if name != "no session" && (!strings.Contains(message, "LocalSystem") || !strings.Contains(message, "--sid")) {
			t.Errorf("%s: the refusal does not say how to enroll: %q", name, message)
		}
	}
	if got := enterpriseACPWindowsTargetError(cause, true); !errors.Is(got, cause) {
		t.Fatal("the refusal dropped its cause")
	}
	// The refusal names the account, not only its SID (GAP-0835).
	previousUser := enterpriseACPUser
	t.Cleanup(func() { enterpriseACPUser = previousUser })
	enterpriseACPUser = `HOST\dcw-user`
	if got := enterpriseACPWindowsTargetError(&enterprisehooks.WindowsTargetSessionUnavailableError{SID: "S-1-5-21-1-2-3-1001"}, false); !strings.Contains(got.Error(), `HOST\dcw-user (S-1-5-21-1-2-3-1001) is not signed in`) {
		t.Fatalf("no-session refusal = %q, want the account named", got)
	}
}

func TestEnterpriseACPRequiresExplicitCentralAllowlist(t *testing.T) {
	previousCfg := cfg
	previousClient, previousAgent, previousProfile := enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = previousClient, previousAgent, previousProfile
	})
	cfg = &config.Config{
		DeploymentMode: "managed_enterprise",
		ACP: config.ACPConfig{
			Enabled:  true,
			Clients:  map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "locked"}},
			Agents:   map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]config.ACPProfile{"locked": {Mode: "action"}},
		},
	}
	enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = "zed", "kiro", "locked"
	if _, err := resolveEnterpriseACPEnrollment(true); err == nil {
		t.Fatal("implicit empty allowlist was accepted for enterprise enrollment")
	}
	// A per-pair binding authorizes its pair as the gateway evaluates it,
	// and a refusal names the pin that disagrees (GAP-0357).
	cfg.Enterprise.Profile = "standalone"
	cfg.ACP.Clients = map[string]config.ACPBinding{"zed": {Enabled: true}}
	cfg.ACP.Agents = map[string]config.ACPBinding{"kiro": {Enabled: true}, "hermes": {Enabled: true, Profile: "watch"}}
	cfg.ACP.Bindings = map[string]config.ACPBinding{"zed/kiro": {Enabled: true, Profile: "locked"}}
	cfg.ACP.Profiles = map[string]config.ACPProfile{
		"locked": {AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"}},
		"watch":  {AllowedClients: []string{"zed"}, AllowedAgents: []string{"hermes"}},
	}
	if _, err := resolveEnterpriseACPEnrollment(true); err != nil && strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("the binding for zed/kiro was not honoured: %v", err)
	}
	enterpriseACPAgent, enterpriseACPProfile = "hermes", "watch"
	if _, err := resolveEnterpriseACPEnrollment(true); err == nil || !strings.Contains(err.Error(), `acp.clients.zed.profile is ""`) {
		t.Fatalf("the refusal does not name the pin that disagrees: %v", err)
	}
	// An over-long name is refused with the rule, not echoed whole
	// (GAP-0688).
	enterpriseACPProfile = strings.Repeat("p", 300)
	if _, err := resolveEnterpriseACPEnrollment(true); err == nil || len(err.Error()) > 300 ||
		!strings.Contains(err.Error(), "at most 64") || !strings.Contains(err.Error(), "locked, watch") {
		t.Fatalf("over-long profile refusal: %v", err)
	}
}

// Redirected Windows output carries an ASCII mark, not a check mark the
// console code page turns into 0xFB (GAP-0709).
func TestEnterpriseACPResultMarkIsASCIIWhenRedirected(t *testing.T) {
	previousCfg, previousASCII, previousJSON := cfg, asciiGlyphs, enterpriseACPJSON
	t.Cleanup(func() { cfg, asciiGlyphs, enterpriseACPJSON = previousCfg, previousASCII, previousJSON })
	cfg = &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	asciiGlyphs, enterpriseACPJSON = func() bool { return true }, false
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	if err := enterpriseACPResult(command, map[string]any{"centrally_revoked": true}, nil); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "OK managed ACP credential revoked") || strings.Contains(got, "✓") {
		t.Fatalf("redirected output = %q", got)
	}
}

func TestEnterpriseACPSetupPathQuotesForPowerShell(t *testing.T) {
	got := enterpriseACPQuotePath(`C:\Program Files\DefenseClaw\bin\gateway.exe`, true)
	if got != `'C:\Program Files\DefenseClaw\bin\gateway.exe'` {
		t.Fatalf("PowerShell path = %q", got)
	}
}

// A setup command is pasted into a POSIX shell, which expands dollar signs
// inside double quotes and needs apostrophes escaped inside single quotes.
func TestEnterpriseACPSetupPathQuotesForUnixShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	path := "/home/person$group/O'Brien data/.defenseclaw"
	quoted := enterpriseACPQuotePath(path, false)
	output, err := exec.Command("sh", "-c", "set -- "+quoted+"; printf %s \"$1\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != path {
		t.Fatalf("shell parsed %q as %q, want %q", quoted, output, path)
	}
}
