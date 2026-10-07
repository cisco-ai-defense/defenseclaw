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
	run(runEnterpriseACPVerify)

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
		if !strings.HasPrefix(message, "enterprise acp: ") || strings.Contains(message, "hook mutation") {
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
}
