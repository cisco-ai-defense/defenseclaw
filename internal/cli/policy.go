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

	"github.com/defenseclaw/defenseclaw/internal/config"
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
		paths, err := resolvePolicyPaths()
		if err != nil {
			return fmt.Errorf("policy: resolve paths: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Validating Rego in %s ...\n", paths.regoDir)

		engine, err := policy.NewExact(paths.regoDir)
		if err != nil {
			return fmt.Errorf("policy: load failed: %w", err)
		}

		if err := engine.Compile(); err != nil {
			return fmt.Errorf("policy: compilation failed:\n%w", err)
		}

		fmt.Println("All Rego modules compiled successfully.")

		data, err := policy.LoadDataExact(paths.regoDir)
		if err != nil {
			return fmt.Errorf("policy: load effective data: %w", err)
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
		paths, err := resolvePolicyPaths()
		if err != nil {
			return fmt.Errorf("policy: resolve paths: %w", err)
		}

		data, err := policy.LoadDataExact(paths.regoDir)
		if err != nil {
			return fmt.Errorf("policy: load effective data: %w", err)
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
		paths, err := resolvePolicyPaths()
		if err != nil {
			return fmt.Errorf("policy: resolve paths: %w", err)
		}

		targetType, _ := cmd.Flags().GetString("target-type")
		targetName, _ := cmd.Flags().GetString("target-name")
		severity, _ := cmd.Flags().GetString("severity")
		findings, _ := cmd.Flags().GetInt("findings")

		if targetName == "" {
			return fmt.Errorf("--target-name is required")
		}

		engine, err := policy.NewExact(paths.regoDir)
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
		paths, err := resolvePolicyPaths()
		if err != nil {
			return fmt.Errorf("policy: resolve paths: %w", err)
		}

		destination, _ := cmd.Flags().GetString("destination")
		port, _ := cmd.Flags().GetInt("port")
		protocol, _ := cmd.Flags().GetString("protocol")
		targetType, _ := cmd.Flags().GetString("target-type")

		if destination == "" {
			return fmt.Errorf("--destination is required")
		}

		engine, err := policy.NewExact(paths.regoDir)
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
		paths, err := resolvePolicyPaths()
		if err != nil {
			return fmt.Errorf("policy: resolve paths: %w", err)
		}

		effectiveData, err := policy.LoadDataExact(paths.regoDir)
		if err != nil {
			return fmt.Errorf("policy: load effective data: %w", err)
		}
		raw, err := json.Marshal(effectiveData)
		if err != nil {
			return fmt.Errorf("policy: encode effective data: %w", err)
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

type resolvedPolicyPaths struct {
	rootDir  string
	regoDir  string
	dataPath string
}

// resolvePolicyPaths resolves one immutable layout for every local policy
// command. Current installations use <policy-root>/rego; releases through
// 0.3.x used the flat policy root. Canonical evidence always wins, including a
// data.json without modules, so an incomplete or malformed canonical layout
// cannot silently downgrade to stale flat policy data.
func resolvePolicyPaths() (resolvedPolicyPaths, error) {
	root, err := resolvePolicyRoot()
	if err != nil {
		return resolvedPolicyPaths{}, err
	}

	nestedDir, err := resolveContainedPolicyPath(root, filepath.Join(root, "rego"))
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("resolve canonical Rego directory: %w", err)
	}
	nestedData, err := resolveContainedPolicyPath(root, filepath.Join(nestedDir, "data.json"))
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("resolve canonical policy data: %w", err)
	}
	nestedModules, err := policyDirectoryHasRego(root, nestedDir)
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("inspect canonical Rego directory: %w", err)
	}
	nestedDataExists, err := policyDataFileExists(nestedData)
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("inspect canonical policy data: %w", err)
	}

	paths := resolvedPolicyPaths{rootDir: root}
	if nestedModules || nestedDataExists {
		paths.regoDir = nestedDir
		paths.dataPath = nestedData
	} else {
		flatData, err := resolveContainedPolicyPath(root, filepath.Join(root, "data.json"))
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("resolve legacy policy data: %w", err)
		}
		flatModules, err := policyDirectoryHasRego(root, root)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect legacy Rego directory: %w", err)
		}
		flatDataExists, err := policyDataFileExists(flatData)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect legacy policy data: %w", err)
		}
		if flatModules || flatDataExists {
			paths.regoDir = root
			paths.dataPath = flatData
		} else {
			paths.regoDir = nestedDir
			paths.dataPath = nestedData
		}
	}

	// Reject another policy generation below the selected canonical directory.
	// This keeps the selection unambiguous even for future engine callers that
	// still recognize a nested rego directory.
	if paths.regoDir != root {
		deeperDir, err := resolveContainedPolicyPath(root, filepath.Join(paths.regoDir, "rego"))
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("resolve nested Rego directory: %w", err)
		}
		deeperData, err := resolveContainedPolicyPath(root, filepath.Join(deeperDir, "data.json"))
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("resolve nested policy data: %w", err)
		}
		deeperModules, err := policyDirectoryHasRego(root, deeperDir)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect nested Rego directory: %w", err)
		}
		deeperDataExists, err := policyDataFileExists(deeperData)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect nested policy data: %w", err)
		}
		if deeperModules || deeperDataExists {
			return resolvedPolicyPaths{}, fmt.Errorf("policy root contains an unsupported nested rego/rego layout")
		}
	}

	if err := validatePolicyEnginePaths(root, paths.regoDir); err != nil {
		return resolvedPolicyPaths{}, err
	}
	return paths, nil
}

func resolvePolicyRoot() (string, error) {
	root := ""
	if cfg != nil {
		if configured := strings.TrimSpace(cfg.PolicyDir); configured != "" {
			root = configured
		} else if dataDir := strings.TrimSpace(cfg.DataDir); dataDir != "" {
			root = filepath.Join(dataDir, "policies")
		}
	}
	if root == "" {
		dataDir := strings.TrimSpace(config.DefaultDataPath())
		if dataDir == "" {
			return "", fmt.Errorf("managed data directory is empty")
		}
		root = filepath.Join(dataDir, "policies")
	}

	resolved, err := canonicalPolicyPath(root)
	if err != nil {
		return "", fmt.Errorf("resolve policy root: %w", err)
	}
	if info, statErr := os.Stat(resolved); statErr == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("policy root is not a directory")
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect policy root: %w", statErr)
	}
	return resolved, nil
}

func resolveContainedPolicyPath(root, candidate string) (string, error) {
	clean := filepath.Clean(candidate)
	if !policyPathContained(root, clean) {
		return "", fmt.Errorf("policy path escapes configured root")
	}
	resolved, err := canonicalPolicyPath(clean)
	if err != nil {
		return "", err
	}
	if !policyPathContained(root, resolved) {
		return "", fmt.Errorf("resolved policy path escapes configured root")
	}
	return resolved, nil
}

func canonicalPolicyPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("path contains NUL")
	}
	if policyPathHasParentSegment(path) {
		return "", fmt.Errorf("path contains a parent segment")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}

	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("normalize path: %w", err)
	}
	if err := validatePolicyPlatformPath(absolute); err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("policy path is a symbolic link")
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect path: %w", statErr)
	}

	resolved, err := resolveExistingPolicyPathPrefix(absolute)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	if err := validatePolicyPlatformPath(resolved); err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func resolveExistingPolicyPathPrefix(absolute string) (string, error) {
	candidate := absolute
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return filepath.Clean(absolute), nil
		}
		suffix = append(suffix, filepath.Base(candidate))
		candidate = parent
	}
}

func policyDirectoryHasRego(root, dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}
		modulePath, err := resolveContainedPolicyPath(root, filepath.Join(dir, entry.Name()))
		if err != nil {
			return false, err
		}
		info, err := os.Lstat(modulePath)
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("Rego module is not a regular file")
		}
		found = true
	}
	return found, nil
}

func policyDataFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("policy data is not a regular file")
	}
	return true, nil
}

func validatePolicyEnginePaths(root, regoDir string) error {
	supplemental, err := resolveContainedPolicyPath(root, filepath.Join(regoDir, "data-sandbox.json"))
	if err != nil {
		return fmt.Errorf("resolve supplemental policy data: %w", err)
	}
	if _, err := policyDataFileExists(supplemental); err != nil {
		return fmt.Errorf("inspect supplemental policy data: %w", err)
	}
	return nil
}

func policyPathContained(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func policyPathHasParentSegment(path string) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
