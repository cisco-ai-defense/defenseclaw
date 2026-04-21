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
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/policy"
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyEvaluateCmd)
	policyCmd.AddCommand(policyEvaluateFirewallCmd)
	policyCmd.AddCommand(policyReloadCmd)
	policyCmd.AddCommand(policyDomainsCmd)

	policyEvaluateCmd.Flags().String("target-type", "skill", "Target type (skill, mcp, plugin)")
	policyEvaluateCmd.Flags().String("target-name", "", "Target name to evaluate")
	policyEvaluateCmd.Flags().String("severity", "", "Max severity of scan result (empty = pre-scan)")
	policyEvaluateCmd.Flags().Int("findings", 0, "Number of findings")

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

// ---------------------------------------------------------------------------
// policy validate
// ---------------------------------------------------------------------------

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Compile-check all Rego modules and validate data.json",
	RunE: func(_ *cobra.Command, _ []string) error {
		regoDir := resolveRegoDir()
		if regoDir == "" {
			return fmt.Errorf("policy: cannot resolve rego directory — set policy_dir in config")
		}

		fmt.Fprintf(os.Stderr, "Validating Rego in %s ...\n", regoDir)

		engine, err := policy.New(regoDir)
		if err != nil {
			return fmt.Errorf("policy: load failed: %w", err)
		}

		if err := engine.Compile(); err != nil {
			return fmt.Errorf("policy: compilation failed:\n%w", err)
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
