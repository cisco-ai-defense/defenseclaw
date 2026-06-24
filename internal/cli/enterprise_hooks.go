// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

var (
	enterpriseHookConnector    string
	enterpriseHookUser         string
	enterpriseHookUserHome     string
	enterpriseHookUID          int
	enterpriseHookGID          int
	enterpriseHookDataDir      string
	enterpriseHookAPIAddr      string
	enterpriseHookProxyAddr    string
	enterpriseHookAgentVersion string
	enterpriseHookManifest     string
	enterpriseHookJSON         bool
)

const defaultEnterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
const hookGuardianStateFile = "hook_guardian_state.json"

var enterpriseCmd = &cobra.Command{
	Use:   "enterprise",
	Short: "Enterprise deployment maintenance commands",
	Long: `Enterprise maintenance commands for administrator-owned DefenseClaw
deployments. These commands are intended for root/MDM/systemd use, not for
standard users.`,
}

var enterpriseHooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Install and repair per-user hook connectors",
}

var enterpriseHooksInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install or repair a hook-native connector for one interactive user",
	Long: `Install or repair DefenseClaw hook wiring for one interactive user's
agent configuration.

The hardened gateway service should not be granted write access to /home.
Instead, run this command as an administrator for each protected user, or from
a systemd timer/MDM guardian. First-time installs require the agent's native
hook config file to already exist, so broad process discovery cannot create a
new app profile from scratch.`,
	RunE: runEnterpriseHooksInstall,
}

var enterpriseHooksReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Install or repair all enabled per-user hook targets from a manifest",
	Long: `Reconcile every enabled hook target from an administrator-owned manifest.

The manifest is the enterprise guardian's allow-list. It prevents a privileged
repair job from scanning every home directory or writing into service accounts
by accident. Each enabled target is installed or repaired independently; the
command reports every result and exits non-zero when any target fails.`,
	RunE: runEnterpriseHooksReconcile,
}

func init() {
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookConnector, "connector", "",
		"Hook-native connector to install or repair (for example codex or claudecode)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookUser, "user", "",
		"Target local user name (resolves home, uid, and gid)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookUserHome, "user-home", "",
		"Target user's home directory (required when --user is omitted)")
	enterpriseHooksInstallCmd.Flags().IntVar(&enterpriseHookUID, "uid", -1,
		"Target user uid (defaults to --user lookup or user-home owner)")
	enterpriseHooksInstallCmd.Flags().IntVar(&enterpriseHookGID, "gid", -1,
		"Target user gid (defaults to --user lookup or user-home owner)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookDataDir, "data-dir", "",
		"Per-user DefenseClaw data dir for hook scripts and token (default: <user-home>/.defenseclaw)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookAgentVersion, "agent-version", "",
		"Raw local agent version used for hook-contract validation")
	enterpriseHooksInstallCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksReconcileCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksCmd.AddCommand(enterpriseHooksInstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksReconcileCmd)
	enterpriseCmd.AddCommand(enterpriseHooksCmd)
	rootCmd.AddCommand(enterpriseCmd)
}

func runEnterpriseHooksInstall(cmd *cobra.Command, _ []string) error {
	if cfg == nil {
		return fmt.Errorf("enterprise hooks install: config is not loaded")
	}
	target, err := resolveEnterpriseHookTarget()
	if err != nil {
		return err
	}
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	token, err := enterpriseHookScopedToken(cfg.DataDir, enterpriseHookConnector)
	if err != nil {
		return err
	}

	opts := enterprisehooks.InstallOptions{
		ConnectorName: enterpriseHookConnector,
		UserHome:      target.home,
		OwnerUID:      target.uid,
		OwnerGID:      target.gid,
		DataDir:       enterpriseHookDataDir,
		APIAddr:       apiAddr,
		ProxyAddr:     proxyAddr,
		APIToken:      token,
		HookFailMode:  cfg.EffectiveHookFailModeForConnector(enterpriseHookConnector),
		GuardrailMode: cfg.EffectiveGuardrailModeForConnector(enterpriseHookConnector),
		HILTEnabled:   cfg.EffectiveHILTForConnector(enterpriseHookConnector).Enabled,
		AgentVersion:  enterpriseHookAgentVersion,
		WorkspaceDir:  cfg.ConnectorWorkspaceDir(),
		Registry:      newConnectorRegistryWithPlugins(),
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	result, err := enterprisehooks.Install(ctx, opts)
	if err != nil {
		if enterpriseHookJSON {
			payload := map[string]any{"ok": false, "error": err.Error()}
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
			return fmt.Errorf("enterprise hooks install failed")
		}
		return err
	}
	if enterpriseHookJSON {
		payload := map[string]any{"ok": true, "result": result}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s %s hooks installed for %s\n", Style("✓", "fg=green", "bold"), result.Connector, result.UserHome)
	return nil
}

type enterpriseHookReconcileRow struct {
	User      string                         `json:"user,omitempty"`
	UserHome  string                         `json:"user_home,omitempty"`
	Connector string                         `json:"connector"`
	OK        bool                           `json:"ok"`
	Error     string                         `json:"error,omitempty"`
	Result    *enterprisehooks.InstallResult `json:"result,omitempty"`
}

func runEnterpriseHooksReconcile(cmd *cobra.Command, _ []string) error {
	if cfg == nil {
		return fmt.Errorf("enterprise hooks reconcile: config is not loaded")
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := managed.ValidateTrustedFilePath(enterpriseHookManifest, "hook guardian manifest"); err != nil {
			return fmt.Errorf("enterprise hooks reconcile: manifest trust check failed: %w", err)
		}
	}
	manifest, err := enterprisehooks.LoadManifest(enterpriseHookManifest)
	if err != nil {
		return err
	}
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	registry := newConnectorRegistryWithPlugins()
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	rows := make([]enterpriseHookReconcileRow, 0, len(manifest.Targets))
	failures := 0
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			Connector: strings.TrimSpace(target.Connector),
		}
		token := ""
		resolved, err := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.DataDir)
		if err == nil {
			var tokenErr error
			token, tokenErr = enterpriseHookScopedToken(cfg.DataDir, target.Connector)
			if tokenErr != nil {
				err = tokenErr
			}
		}
		if err == nil {
			opts := enterprisehooks.InstallOptions{
				ConnectorName: target.Connector,
				UserHome:      resolved.home,
				OwnerUID:      resolved.uid,
				OwnerGID:      resolved.gid,
				DataDir:       strings.TrimSpace(target.DataDir),
				APIAddr:       apiAddr,
				ProxyAddr:     proxyAddr,
				APIToken:      token,
				HookFailMode:  cfg.EffectiveHookFailModeForConnector(target.Connector),
				GuardrailMode: cfg.EffectiveGuardrailModeForConnector(target.Connector),
				HILTEnabled:   cfg.EffectiveHILTForConnector(target.Connector).Enabled,
				AgentVersion:  strings.TrimSpace(target.AgentVersion),
				WorkspaceDir:  cfg.ConnectorWorkspaceDir(),
				Registry:      registry,
			}
			var result enterprisehooks.InstallResult
			result, err = enterprisehooks.Install(ctx, opts)
			if err == nil {
				row.OK = true
				row.UserHome = result.UserHome
				row.Connector = result.Connector
				row.Result = &result
			}
		}
		if err != nil {
			failures++
			row.OK = false
			row.Error = err.Error()
		}
		rows = append(rows, row)
	}

	stateErr := writeEnterpriseHookGuardianState(cfg.DataDir, enterpriseHookManifest, rows, failures)

	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":       failures == 0 && stateErr == nil,
			"manifest": enterpriseHookManifest,
			"results":  rows,
		}
		if stateErr != nil {
			payload["state_error"] = stateErr.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		if failures > 0 || stateErr != nil {
			if stateErr != nil {
				return fmt.Errorf("enterprise hooks reconcile state write failed: %w", stateErr)
			}
			return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", failures)
		}
		return nil
	}

	for _, row := range rows {
		label := row.Connector
		if row.User != "" {
			label += "@" + row.User
		} else if row.UserHome != "" {
			label += "@" + row.UserHome
		}
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s reconciled\n", Style("✓", "fg=green", "bold"), label)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %s\n", Style("✗", "fg=red", "bold"), label, row.Error)
		}
	}
	if stateErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s hook guardian state: %s\n", Style("✗", "fg=red", "bold"), stateErr.Error())
		return fmt.Errorf("enterprise hooks reconcile state write failed: %w", stateErr)
	}
	if failures > 0 {
		return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", failures)
	}
	return nil
}

type enterpriseHookGuardianState struct {
	Version      int                          `json:"version"`
	UpdatedAt    string                       `json:"updated_at"`
	Manifest     string                       `json:"manifest"`
	OK           bool                         `json:"ok"`
	TargetCount  int                          `json:"target_count"`
	SuccessCount int                          `json:"success_count"`
	FailureCount int                          `json:"failure_count"`
	Results      []enterpriseHookReconcileRow `json:"results"`
}

func writeEnterpriseHookGuardianState(dataDir, manifest string, rows []enterpriseHookReconcileRow, failures int) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return fmt.Errorf("no data directory configured")
	}
	successes := 0
	for _, row := range rows {
		if row.OK {
			successes++
		}
	}
	state := enterpriseHookGuardianState{
		Version:      1,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Manifest:     strings.TrimSpace(manifest),
		OK:           failures == 0,
		TargetCount:  len(rows),
		SuccessCount: successes,
		FailureCount: failures,
		Results:      rows,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(dataDir, hookGuardianStateFile)
	if err := safefile.Write(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

type enterpriseHookTarget struct {
	home string
	uid  int
	gid  int
}

func resolveEnterpriseHookTarget() (enterpriseHookTarget, error) {
	return resolveEnterpriseHookTargetValues(enterpriseHookUser, enterpriseHookUserHome, enterpriseHookUID, enterpriseHookGID, enterpriseHookDataDir)
}

func resolveEnterpriseHookTargetValues(userName, userHome string, uid, gid int, dataDir string) (enterpriseHookTarget, error) {
	target := enterpriseHookTarget{
		home: strings.TrimSpace(userHome),
		uid:  uid,
		gid:  gid,
	}
	if name := strings.TrimSpace(userName); name != "" {
		u, err := user.Lookup(name)
		if err != nil {
			return target, fmt.Errorf("enterprise hooks install: lookup user %q: %w", name, err)
		}
		if target.home == "" {
			target.home = u.HomeDir
		}
		if target.uid < 0 {
			uid, err := strconv.Atoi(u.Uid)
			if err != nil {
				return target, fmt.Errorf("enterprise hooks install: parse uid for %q: %w", name, err)
			}
			target.uid = uid
		}
		if target.gid < 0 {
			gid, err := strconv.Atoi(u.Gid)
			if err != nil {
				return target, fmt.Errorf("enterprise hooks install: parse gid for %q: %w", name, err)
			}
			target.gid = gid
		}
	}
	if target.home == "" {
		return target, fmt.Errorf("enterprise hooks install: --user or --user-home is required")
	}
	if dataDir := strings.TrimSpace(dataDir); dataDir != "" && !filepath.IsAbs(dataDir) {
		return target, fmt.Errorf("enterprise hooks install: --data-dir must be absolute")
	}
	return target, nil
}

func enterpriseHookScopedToken(dataDir, connectorName string) (string, error) {
	connectorName = strings.TrimSpace(connectorName)
	if connectorName == "" {
		return "", fmt.Errorf("enterprise hooks: connector is required before minting hook API token")
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("enterprise hooks: config data_dir is required before minting hook API token")
	}
	token, err := connector.EnsureHookAPIToken(dataDir, connectorName)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: ensure scoped hook API token: %w", err)
	}
	if err := alignEnterpriseHookScopedTokenOwner(dataDir, connectorName); err != nil {
		return "", err
	}
	return token, nil
}

func intPtrValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
