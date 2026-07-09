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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyValidateRulePackCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyEvaluateCmd)
	policyCmd.AddCommand(policyEvaluateFirewallCmd)
	policyCmd.AddCommand(policyReloadCmd)
	policyCmd.AddCommand(policyDomainsCmd)

	policyEvaluateCmd.Flags().String("target-type", "skill", "Target type (skill, mcp, plugin)")
	policyEvaluateCmd.Flags().String("target-name", "", "Target name to evaluate")
	policyEvaluateCmd.Flags().String("severity", "", "Max severity of scan result (empty = pre-scan)")
	policyEvaluateCmd.Flags().Int("findings", 0, "Number of findings")
	policyValidateCmd.Flags().StringVar(&policyValidateRegoDir, "rego-dir", "", "Policy Rego directory to validate")
	policyValidateCmd.Flags().StringVar(&policyValidateAgentControlCandidate, "candidate-agent-control", "", "Validate this Agent Control supplemental file instead of the active file")
	policyValidateRulePackCmd.Flags().StringVar(&policyValidateRulePackBaseDir, "base-dir", "", "Operator rule-pack directory to preserve beneath the overlay")
	policyValidateRulePackCmd.Flags().StringVar(&policyValidateRulePackOverlayDir, "overlay-dir", "", "Managed rules-only overlay directory to validate")
	policyValidateRulePackCmd.Flags().StringVar(&policyValidateRulePackRegexSource, "regex-source", guardrail.RegexSourceHybrid, "Regex policy source (local, agent_control, hybrid)")
	// Native pre-publication validation must be side-effect free and usable
	// before the gateway/audit database is running. An explicit --rego-dir is
	// self-contained and skips root bootstrap; the normal no-flag command keeps
	// the existing config-backed policy_dir resolution and full CLI lifecycle.
	policyValidateCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(policyValidateRegoDir) != "" {
			return nil
		}
		return rootCmd.PersistentPreRunE(cmd, args)
	}
	policyValidateRulePackCmd.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }

	policyEvaluateFirewallCmd.Flags().String("destination", "", "Destination hostname or IP")
	policyEvaluateFirewallCmd.Flags().Int("port", 443, "Destination port")
	policyEvaluateFirewallCmd.Flags().String("protocol", "tcp", "Protocol (tcp/udp)")
	policyEvaluateFirewallCmd.Flags().String("target-type", "skill", "Target type context")
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage and inspect OPA policies",
	Long:  "Validate, inspect, evaluate, and reload DefenseClaw OPA policies.",
}

var (
	policyValidateRegoDir               string
	policyValidateAgentControlCandidate string
	policyValidateRulePackBaseDir       string
	policyValidateRulePackOverlayDir    string
	policyValidateRulePackRegexSource   string
)

// ---------------------------------------------------------------------------
// policy validate
// ---------------------------------------------------------------------------

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Compile-check all Rego modules and validate data.json",
	RunE: func(_ *cobra.Command, _ []string) error {
		regoDir := policyValidateRegoDir
		if strings.TrimSpace(regoDir) == "" {
			regoDir = resolveRegoDir()
		}
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory — set policy_dir in config")
		}
		regoDir = normalizePolicyRegoDir(regoDir)

		candidate := policyValidateAgentControlCandidate
		if strings.TrimSpace(candidate) != "" {
			staged, cleanup, err := stageAgentControlCandidate(regoDir, candidate)
			if err != nil {
				return err
			}
			defer cleanup()
			regoDir = staged
		}

		fmt.Fprintf(os.Stderr, "Validating Rego in %s ...\n", regoDir)

		engine, err := policy.New(regoDir)
		if err != nil {
			return fmt.Errorf("policy: load failed: %w", err)
		}

		if err := engine.Compile(); err != nil {
			return fmt.Errorf("policy: compilation failed:\n%w", err)
		}
		if strings.TrimSpace(candidate) != "" {
			if err := validateAgentControlGuardrailSmoke(engine); err != nil {
				return fmt.Errorf("policy: Agent Control smoke validation failed: %w", err)
			}
			status := engine.Status().AgentControl
			fmt.Printf("Agent Control candidate: artifact_digest=%s source_digest=%s\n", status.ArtifactDigest, status.SourceDigest)
		}

		fmt.Println("All Rego modules compiled successfully.")

		dataPath := filepath.Join(regoDir, "data.json")
		raw, err := os.ReadFile(dataPath)
		if err != nil {
			return fmt.Errorf("policy: read data.json: %w", err)
		}

		var data map[string]interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			return fmt.Errorf("policy: invalid data.json: %w", err)
		}

		required := []string{"config", "actions", "severity_ranking"}
		for _, key := range required {
			if _, ok := data[key]; !ok {
				fmt.Fprintf(os.Stderr, "warning: data.json missing key: %s\n", key)
			}
		}

		fmt.Println("data.json schema: OK")
		return nil
	},
}

func validateAgentControlGuardrailSmoke(engine *policy.Engine) error {
	inputs := []policy.GuardrailInput{
		{
			Direction:   "prompt",
			Mode:        "action",
			ScannerMode: "local",
			LocalResult: &policy.GuardrailScanResult{Action: "allow", Severity: "NONE", Findings: []string{}},
		},
		{
			Direction:   "prompt",
			Mode:        "action",
			ScannerMode: "local",
			LocalResult: &policy.GuardrailScanResult{Action: "alert", Severity: "HIGH", Findings: []string{"smoke"}},
		},
	}
	for i, input := range inputs {
		out, err := engine.EvaluateGuardrail(context.Background(), input)
		if err != nil {
			return fmt.Errorf("case %d: %w", i, err)
		}
		switch out.Action {
		case "allow", "alert", "block", "confirm":
		default:
			return fmt.Errorf("case %d returned invalid action %q", i, out.Action)
		}
	}
	return nil
}

func stageAgentControlCandidate(regoDir, candidate string) (string, func(), error) {
	info, err := os.Stat(regoDir)
	if err != nil || !info.IsDir() {
		return "", func() {}, fmt.Errorf("policy: invalid rego directory %s", regoDir)
	}
	rawCandidate, err := os.ReadFile(candidate)
	if err != nil {
		return "", func() {}, fmt.Errorf("policy: read Agent Control candidate: %w", err)
	}
	staged, err := os.MkdirTemp("", "defenseclaw-policy-validate-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(staged) }
	entries, err := os.ReadDir(regoDir)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".rego" && name != "data.json" && name != "data-sandbox.json" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(regoDir, name))
		if readErr != nil {
			cleanup()
			return "", func() {}, readErr
		}
		if writeErr := os.WriteFile(filepath.Join(staged, name), raw, 0o600); writeErr != nil {
			cleanup()
			return "", func() {}, writeErr
		}
	}
	if err := os.WriteFile(filepath.Join(staged, "data-agent-control.json"), rawCandidate, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return staged, cleanup, nil
}

func normalizePolicyRegoDir(policyDir string) string {
	nested := filepath.Join(policyDir, "rego")
	if info, err := os.Stat(nested); err == nil && info.IsDir() {
		return nested
	}
	return policyDir
}

// ---------------------------------------------------------------------------
// policy validate-rule-pack — strict managed-overlay validation
// ---------------------------------------------------------------------------

var policyValidateRulePackCmd = &cobra.Command{
	Use:   "validate-rule-pack",
	Short: "Strictly validate a managed rules-only overlay",
	RunE: func(_ *cobra.Command, _ []string) error {
		overlayDir := strings.TrimSpace(policyValidateRulePackOverlayDir)
		if overlayDir == "" {
			return fmt.Errorf("policy: --overlay-dir is required")
		}
		pack, err := guardrail.LoadRulePackForRegexSource(
			policyValidateRulePackBaseDir,
			[]string{overlayDir},
			policyValidateRulePackRegexSource,
		)
		if err != nil {
			return fmt.Errorf("policy: managed rule-pack validation failed: %w", err)
		}
		fmt.Printf("Managed rule-pack overlay valid (%d rule files).\n", len(pack.RuleFiles))
		return nil
	},
}

// ---------------------------------------------------------------------------
// policy show
// ---------------------------------------------------------------------------

var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display the current OPA data.json policy configuration",
	RunE: func(_ *cobra.Command, _ []string) error {
		regoDir := resolveRegoDir()
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory")
		}

		dataPath := filepath.Join(regoDir, "data.json")
		raw, err := os.ReadFile(dataPath)
		if err != nil {
			return fmt.Errorf("policy: read data.json: %w", err)
		}

		var data map[string]interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			return fmt.Errorf("policy: parse data.json: %w", err)
		}

		out, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

// ---------------------------------------------------------------------------
// policy evaluate — dry-run admission
// ---------------------------------------------------------------------------

var policyEvaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Dry-run the admission policy for a given input",
	RunE: func(cmd *cobra.Command, _ []string) error {
		regoDir := resolveRegoDir()
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory")
		}

		targetType, _ := cmd.Flags().GetString("target-type")
		targetName, _ := cmd.Flags().GetString("target-name")
		severity, _ := cmd.Flags().GetString("severity")
		findings, _ := cmd.Flags().GetInt("findings")

		if targetName == "" {
			return fmt.Errorf("--target-name is required")
		}

		engine, err := policy.New(regoDir)
		if err != nil {
			return err
		}

		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: targetName,
			Path:       "/dry-run",
		}

		if severity != "" {
			input.ScanResult = &policy.ScanResultInput{
				MaxSeverity:   severity,
				TotalFindings: findings,
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		out, err := engine.Evaluate(ctx, input)
		if err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}

		result, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(result))
		return nil
	},
}

// ---------------------------------------------------------------------------
// policy evaluate-firewall — dry-run firewall
// ---------------------------------------------------------------------------

var policyEvaluateFirewallCmd = &cobra.Command{
	Use:   "evaluate-firewall",
	Short: "Dry-run the firewall policy for a given destination",
	RunE: func(cmd *cobra.Command, _ []string) error {
		regoDir := resolveRegoDir()
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory")
		}

		destination, _ := cmd.Flags().GetString("destination")
		port, _ := cmd.Flags().GetInt("port")
		protocol, _ := cmd.Flags().GetString("protocol")
		targetType, _ := cmd.Flags().GetString("target-type")

		if destination == "" {
			return fmt.Errorf("--destination is required")
		}

		engine, err := policy.New(regoDir)
		if err != nil {
			return err
		}

		input := policy.FirewallInput{
			TargetType:  targetType,
			Destination: destination,
			Port:        port,
			Protocol:    protocol,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		out, err := engine.EvaluateFirewall(ctx, input)
		if err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}

		result, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(result))
		return nil
	},
}

// ---------------------------------------------------------------------------
// policy reload — tell running daemon to hot-reload
// ---------------------------------------------------------------------------

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Tell the running sidecar daemon to reload OPA policies",
	RunE: func(_ *cobra.Command, _ []string) error {
		port := 18790
		bind := "127.0.0.1"
		if cfg != nil {
			port = cfg.Gateway.APIPort
			if cfg.Gateway.APIBind != "" {
				bind = cfg.Gateway.APIBind
			}
		}

		url := fmt.Sprintf("http://%s:%d/policy/reload", bind, port)

		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "cli")
		// ("policy reload client omits the
		// required gateway token"): /policy/reload is wrapped
		// in tokenAuth, which exempts only GET /health. Without
		// these headers the sidecar returns 401 and the CLI
		// cannot hot-reload policies on a normally-configured
		// install. Resolve the gateway token from
		// cfg.Gateway.ResolvedToken() (which honours config +
		// env precedence) and attach it under both the bearer
		// and the explicit X-DefenseClaw-Token header so we
		// stay compatible with both intake paths.
		if cfg != nil {
			if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-DefenseClaw-Token", token)
			} else {
				return fmt.Errorf("policy reload: no gateway token configured (set DEFENSECLAW_GATEWAY_TOKEN or run 'defenseclaw setup gateway')")
			}
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("cannot reach sidecar at %s — is it running?", url)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("reload failed (HTTP %d): %s", resp.StatusCode, string(body))
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err == nil {
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Println(string(body))
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// policy domains — list allowed/blocked domains from data.json
// ---------------------------------------------------------------------------

var policyDomainsCmd = &cobra.Command{
	Use:   "domains",
	Short: "List firewall domain allowlist and blocklist from active policy",
	RunE: func(_ *cobra.Command, _ []string) error {
		regoDir := resolveRegoDir()
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory")
		}

		dataPath := filepath.Join(regoDir, "data.json")
		raw, err := os.ReadFile(dataPath)
		if err != nil {
			return fmt.Errorf("policy: read data.json: %w", err)
		}

		var data struct {
			Firewall struct {
				DefaultAction       string   `json:"default_action"`
				BlockedDestinations []string `json:"blocked_destinations"`
				AllowedDomains      []string `json:"allowed_domains"`
				AllowedPorts        []int    `json:"allowed_ports"`
			} `json:"firewall"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return fmt.Errorf("policy: parse data.json: %w", err)
		}

		fmt.Printf("Default action: %s\n", data.Firewall.DefaultAction)
		fmt.Printf("Allowed ports:  %v\n\n", data.Firewall.AllowedPorts)

		fmt.Println("Blocked destinations:")
		for _, d := range data.Firewall.BlockedDestinations {
			fmt.Printf("  - %s\n", d)
		}
		fmt.Println()

		fmt.Println("Allowed domains:")
		for _, d := range data.Firewall.AllowedDomains {
			fmt.Printf("  + %s\n", d)
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func resolveRegoDir() string {
	if cfg != nil && cfg.PolicyDir != "" {
		if info, err := os.Stat(cfg.PolicyDir); err == nil && info.IsDir() {
			dataJSON := filepath.Join(cfg.PolicyDir, "data.json")
			if _, err := os.Stat(dataJSON); err == nil {
				return cfg.PolicyDir
			}
		}
	}

	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "..", "policies", "rego")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	wd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(wd, "policies", "rego")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	return ""
}
