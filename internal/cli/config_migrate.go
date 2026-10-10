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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// config is the operator-facing config group of the gateway binary. Like
// config-v8 it runs without the root pre-run, which would load the very
// file being migrated. Main has no config group, so a Secure Client
// computer leaves it out of its help; it stays runnable there and answers
// that the config stays on config_version 8 (issue #1092, GAP-0270).
var configCmd = &cobra.Command{
	Use:         "config",
	Short:       "Migrate config.yaml",
	Annotations: map[string]string{secureClientHiddenAnnotation: "true"},
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var (
	configMigrateTo      int
	configMigratePath    string
	configMigrateDataDir string
	configMigrateDryRun  bool
	configMigrateJSON    bool
	configMigrateAck     bool
)

var configMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate config.yaml to config_version 9 (data.json, *_actions and audit.db block lists move into config)",
	Long: "Moves the admission policy from policies/rego/data.json, the skill/mcp/plugin_actions keys, " +
		"rule_pack_dir, the v8 scanner keys, update_check, a leftover privacy section and (on a per-user install) the operator " +
		"block/allow entries of audit.db into config.yaml. It keeps config.yaml.v8.bak and writes " +
		"migration-v9.json with every value moved and every conflict. --dry-run changes nothing.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if configMigrateTo != config.ConfigVersionV9 {
			return fmt.Errorf("config migrate supports --to %d only", config.ConfigVersionV9)
		}
		path := strings.TrimSpace(configMigratePath)
		if path == "" && strings.TrimSpace(configMigrateDataDir) != "" {
			path = filepath.Join(configMigrateDataDir, "config.yaml")
		}
		if path == "" {
			path = config.ConfigPath()
		}
		if raw, err := os.ReadFile(path); err == nil && config.SecureClientSource(raw) {
			// Nothing to do, not a failure: config_version 8 is current for this
			// file, so an installer or `defenseclaw migrate` that runs this
			// command keeps succeeding (issue #1092).
			if configMigrateJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"migrated": false, "dry_run": configMigrateDryRun, "written": []string{}, "record": map[string]any{},
				})
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s is a Secure Client config, which stays on config_version 8; nothing to migrate.\n", path)
			return err
		}
		if configMigrateAck {
			if err := config.AcknowledgeMigrationV9(path); err != nil {
				return fmt.Errorf("acknowledge %s: %w", config.MigrationRecordPath(path), err)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Marked the config_version 9 migration record as read.")
			return err
		}
		input, err := configMigrateV9Input(path)
		if err != nil {
			return err
		}
		input.DryRun = configMigrateDryRun
		result, err := config.MigrateV9(context.Background(), input)
		if err != nil {
			return err
		}
		return printConfigMigrateResult(cmd, result)
	},
}

func init() {
	configMigrateCmd.Flags().IntVar(&configMigrateTo, "to", config.ConfigVersionV9, "target config_version")
	configMigrateCmd.Flags().StringVar(&configMigratePath, "config", "", "config.yaml (default: <data-dir>/config.yaml)")
	configMigrateCmd.Flags().StringVar(&configMigrateDataDir, "data-dir", "", "data directory holding config.yaml")
	configMigrateCmd.Flags().BoolVar(&configMigrateDryRun, "dry-run", false, "show what would move; write nothing")
	configMigrateCmd.Flags().BoolVar(&configMigrateJSON, "json", false, "print the result as JSON")
	configMigrateCmd.Flags().BoolVar(&configMigrateAck, "ack", false, "mark migration-v9.json as read")
	configCmd.AddCommand(configMigrateCmd)
	rootCmd.AddCommand(configCmd)
}

// rebaseRulePackForMigration is guardrail.PlanRulePackRebase in the config
// package's terms (GAP-0360).
func rebaseRulePackForMigration(dir string) (*config.RulePackRebasePlan, error) {
	plan, err := guardrail.PlanRulePackRebase(dir)
	if err != nil || plan == nil {
		return nil, err
	}
	return &config.RulePackRebasePlan{
		Files: plan.Files, Digest: plan.Digest, Updated: plan.Updated,
		Carried: plan.Carried, Expressed: plan.Expressed, AlertOnly: plan.AlertOnly, Disabled: plan.Disabled,
		Merged: plan.Merged, Linked: plan.Linked, WholeArgument: plan.WholeArgument, Renamed: plan.Renamed,
	}, nil
}

// configMigrateV9Input resolves the data.json and audit.db inputs of the
// config at path. A v8 file the runtime loader refuses (it still carries a key
// the runtime no longer knows, such as update_check or skill_actions) falls
// back to the document's own path keys.
func configMigrateV9Input(path string) (config.MigrateV9Input, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return config.MigrateV9Input{}, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return config.MigrateV9Input{}, fmt.Errorf("read %s: %w", abs, err)
	}
	input := config.MigrateV9Input{
		ConfigPath:     abs,
		Source:         raw,
		RulePackDigest: guardrail.RulePackDigest,
		RebaseRulePack: rebaseRulePackForMigration,
	}
	policyDir, auditDB := "", ""
	if cfg, loadErr := config.LoadRuntimeV8File(abs); loadErr == nil {
		policyDir, auditDB = cfg.PolicyDir, cfg.AuditDB
		input.DataDir = cfg.DataDir
		input.Managed = cfg.StandaloneEnterprise()
	} else {
		var plain struct {
			PolicyDir     string `yaml:"policy_dir"`
			Observability struct {
				Local struct {
					Path string `yaml:"path"`
				} `yaml:"local"`
			} `yaml:"observability"`
		}
		if err := yaml.Unmarshal(raw, &plain); err != nil {
			return config.MigrateV9Input{}, fmt.Errorf("parse %s: %w", abs, err)
		}
		dataDir := config.MigrationDataDir(abs, raw)
		input.DataDir = dataDir
		policyDir = strings.TrimSpace(plain.PolicyDir)
		if policyDir == "" {
			policyDir = filepath.Join(dataDir, "policies")
		}
		auditDB = strings.TrimSpace(plain.Observability.Local.Path)
		if auditDB == "" {
			auditDB = filepath.Join(dataDir, "audit.db")
		}
		input.Managed = config.StandaloneManagedSource(raw)
	}
	if policyDir != "" {
		input.PolicyDir, input.DataJSONPath = config.V8PolicyDataJSON(policyDir)
	}
	input.AuditDBPath = expandMigrationInputPath(auditDB)
	// The migrated document is validated the way the gateway loads it, with
	// the credentials of the data directory's .env: a destination key stored
	// there by `defenseclaw keys set` (the normal layout) must resolve
	// (GAP-0035).
	if input.DataDir != "" {
		loadDotEnvIntoOS(filepath.Join(input.DataDir, ".env"))
	}
	return input, nil
}

// expandMigrationInputPath uses the same ~/ expansion as the gateway's
// in-memory v8 migration for the audit.db path.
func expandMigrationInputPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// migrateManagedStandaloneConfig is the Windows standalone lifecycle's
// config step (the Unix lifecycle does the same inside its transaction): a
// config_version 8 administrator config installed by Setup is migrated to 9
// in place (config.yaml.v8.bak, migration-v9.json, actor lifecycle), and an
// installed config the writer has not recorded gets its
// config.generation.json entry. The caller has already pinned the managed
// standalone environment.
func migrateManagedStandaloneConfig(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	restoreACL, err := keepConfigDACL(path)
	if err != nil {
		return fmt.Errorf("read the access control list of %s: %w", path, err)
	}
	written := []string{configwrite.GenerationPath(path)}
	if config.NeedsMigrationV9(raw) {
		input, err := configMigrateV9Input(path)
		if err != nil {
			return err
		}
		input.Managed = true
		if _, err := config.MigrateV9(ctx, input); err != nil {
			return fmt.Errorf("migrate %s to config_version 9: %w", path, err)
		}
		// Only config-owned files take config.yaml's DACL. MigrateV9 also
		// writes .env and may touch policy files; their ACLs belong to
		// those files, not to the readable config (GAP-0440).
		return restoreACL(append(written, path, path+config.ConfigV8BackupSuffix, config.MigrationRecordPath(path))...)
	}
	if state, err := configwrite.ReadGenerationState(path); err == nil && state.ConfigSHA256 == configwrite.SHA256Hex(raw) {
		// Already recorded, but the record still takes the DACL of the
		// config: an uninstall that keeps state leaves it administrator-only,
		// and the gateway service reads it for its generation (GAP-0293).
		return restoreACL(written...)
	}
	if _, err := configwrite.Locked(ctx, path, configwrite.Options{
		Actor: configwrite.ActorLifecycle, Reason: "enterprise windows ensure",
	}, func() (bool, error) { return true, nil }); err != nil {
		return err
	}
	return restoreACL(written...)
}

// recordRestoredManagedStandaloneConfig records the config.yaml a lifecycle
// rollback put back as a new config generation, as the Unix lifecycle does.
// The rolled-back run may have recorded, and the gateway reported, a
// generation for the config it installed, and the counter never goes back.
// Nothing happens without a generation record (the transaction removes one
// it created) or when the record already names the restored bytes. The file
// is not migrated: a rollback leaves the config as it was.
func recordRestoredManagedStandaloneConfig(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.ConfigSHA256 == configwrite.SHA256Hex(raw) {
		return nil
	}
	restoreACL, err := keepConfigDACL(path)
	if err != nil {
		return fmt.Errorf("read the access control list of %s: %w", path, err)
	}
	if _, err := configwrite.Locked(ctx, path, configwrite.Options{
		Actor: configwrite.ActorLifecycle, Reason: "enterprise windows rollback",
	}, func() (bool, error) { return true, nil }); err != nil {
		return err
	}
	return restoreACL(configwrite.GenerationPath(path))
}

func printConfigMigrateResult(cmd *cobra.Command, result *config.MigrateV9Result) error {
	out := cmd.OutOrStdout()
	already := result.Record.FromVersion == config.ConfigVersionV9
	if configMigrateJSON {
		payload := struct {
			Migrated bool                   `json:"migrated"`
			DryRun   bool                   `json:"dry_run"`
			Written  []string               `json:"written"`
			Record   config.MigrationRecord `json:"record"`
		}{!already && !configMigrateDryRun, configMigrateDryRun, result.Written, result.Record}
		if payload.Written == nil {
			payload.Written = []string{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	if already {
		_, err := fmt.Fprintln(out, "config.yaml is already config_version 9; nothing to migrate.")
		return err
	}
	verb := "Migrated"
	if configMigrateDryRun {
		verb = "Would migrate"
	}
	r := result.Record
	fmt.Fprintf(out, "%s config.yaml to config_version 9: %d values moved, %d conflicts, %d audit.db entries moved.\n",
		verb, len(r.Moved), len(r.Conflicts), r.ActionsRowsMoved)
	for _, move := range r.Moved {
		fmt.Fprintf(out, "  moved    %s -> %s\n", move.From, move.To)
	}
	for _, conflict := range r.Conflicts {
		fmt.Fprintf(out, "  conflict %s: kept %s, dropped %s (%s)\n", conflict.To, conflict.Kept, conflict.Lost, conflict.Reason)
	}
	for _, removed := range r.Removed {
		fmt.Fprintf(out, "  removed  %s (no reader)\n", removed)
	}
	for _, note := range r.Notes {
		fmt.Fprintf(out, "  note     %s\n", note)
	}
	for _, line := range config.MigratedRuleLines(r) {
		fmt.Fprintf(out, "  rule     %s\n", line)
	}
	if len(result.Written) > 0 {
		fmt.Fprintf(out, "Wrote %s.\n", strings.Join(result.Written, ", "))
	}
	return nil
}
