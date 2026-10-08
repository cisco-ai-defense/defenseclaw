// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
	userData := filepath.Join(userHome, ".defenseclaw")
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
	enterpriseACPUserHome, enterpriseACPUserDataDir, enterpriseACPJSON = userHome, userData, true

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
	// verify tells a published token from a completed setup, and list
	// names who is enrolled and how far they got (GAP-0400).
	if verified := run(runEnterpriseACPVerify); verified["setup_done"] != false {
		t.Fatalf("verify did not report that setup has not run: %v", verified)
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
}

func TestEnterpriseACPSetupPathQuotesForPowerShell(t *testing.T) {
	got := enterpriseACPQuotePath(`C:\Program Files\DefenseClaw\bin\gateway.exe`, true)
	if got != `'C:\Program Files\DefenseClaw\bin\gateway.exe'` {
		t.Fatalf("PowerShell path = %q", got)
	}
}
