// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
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

	enrolled := run(runEnterpriseACPEnroll)
	if next, _ := enrolled["next"].(string); !strings.Contains(next, " --activate") {
		t.Fatalf("inherited action mode was omitted from setup command: %q", next)
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
	credential, err := acp.LoadEnterpriseCredential(serviceData, enrollment.principal, "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := acp.MatchEnterpriseCredential(serviceData, credential.Token); !ok {
		t.Fatal("enrolled token did not authenticate")
	}
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
