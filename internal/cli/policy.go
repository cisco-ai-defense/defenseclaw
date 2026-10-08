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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyTestCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyEvaluateCmd)
	policyCmd.AddCommand(policyReloadCmd)

	policyValidateCmd.Flags().String("rego-dir", "", "Rego directory to validate (default: the configured policy directory)")
	policyTestCmd.Flags().String("rego-dir", "", "Rego directory to test (default: the configured policy directory)")
	policyTestCmd.Flags().BoolP("verbose", "v", false, "Print every test result")

	policyEvaluateCmd.Flags().String("target-type", "skill", "Target type (skill, mcp, plugin)")
	policyEvaluateCmd.Flags().String("target-name", "", "Target name to evaluate")
	policyEvaluateCmd.Flags().String("severity", "", "Max severity of scan result (empty = pre-scan)")
	policyEvaluateCmd.Flags().Int("findings", 0, "Number of findings")
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage and inspect OPA policies",
	Long:  "Validate, inspect, evaluate, and reload DefenseClaw OPA policies.",
}

// policyConfigOnlyPreRunE is the setup of the read-only policy views
// (digest, show, validate): they need the strict runtime config and the
// policy assets, never the audit store, so a short-lived process does not
// become a second SQLite owner. On a standalone managed host an
// administrator's run reads the managed deployment without extra
// environment variables, as status does; a standard user gets the managed
// answer instead of a per-user config that does not exist.
func policyConfigOnlyPreRunE(cmd *cobra.Command, _ []string) error {
	if err := managedStandardUserGatewayRefusal(); err != nil {
		return err
	}
	if err := pinManagedAdministratorEnvironment("policy", func() string {
		return windowsManagedStandardUserViewAnswer("the managed policy", "enterprise policy show --user "+managedHostCurrentAccountName())
	}); err != nil {
		return err
	}
	applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
	return loadGatewayCommandConfigFor(cmd)
}

func policyConfigOnlyPostRun(*cobra.Command, []string) {}

// ---------------------------------------------------------------------------
// policy validate
// ---------------------------------------------------------------------------

var policyValidateCmd = &cobra.Command{
	Use:               "validate",
	Short:             "Compile-check all Rego modules and the admission policy compiled from config.yaml",
	Annotations:       map[string]string{secureClientShortAnnotation: "Compile-check all Rego modules and validate data.json"},
	PersistentPreRunE: policyConfigOnlyPreRunE,
	PersistentPostRun: policyConfigOnlyPostRun,
	RunE: func(cmd *cobra.Command, _ []string) error {
		regoDir, err := policyCommandRegoDir(cmd)
		if err != nil {
			return err
		}
		if cfg != nil && cfg.SecureClientIntegration() {
			return validateSecureClientPolicy(regoDir)
		}

		if _, statErr := os.Stat(regoDir); errors.Is(statErr, fs.ErrNotExist) {
			// The managed packages ship no Rego: the admission policy is
			// compiled from config.yaml alone, so there is nothing to compile.
			fmt.Printf("No Rego directory at %s: the admission policy is compiled from config.yaml alone.\n", regoDir)
		} else {
			fmt.Fprintf(os.Stderr, "Validating Rego in %s ...\n", regoDir)
			if _, err := policy.NewExact(regoDir); errors.Is(err, policy.ErrNoModules) {
				fmt.Printf("No Rego modules in %s: the admission policy is compiled from config.yaml alone.\n", regoDir)
			} else if err != nil {
				return fmt.Errorf("policy: compilation failed:\n%w", err)
			} else {
				fmt.Println("All Rego modules compiled successfully.")
			}
		}

		for _, assetType := range []string{config.AdmissionTypeSkill, config.AdmissionTypeMCP, config.AdmissionTypePlugin} {
			compiled := policy.CompileAdmission(cfg)[assetType]
			fmt.Printf("admission.%s: actions from %s\n", assetType, compiled.Source)
		}
		return nil
	},
}

// validateSecureClientPolicy is policy validate of main, which a Secure
// Client host keeps (issue #1092): data.json is required, then the Rego
// modules compile.
func validateSecureClientPolicy(regoDir string) error {
	fmt.Fprintf(os.Stderr, "Validating Rego in %s ...\n", regoDir)
	data, err := policy.LoadSecureClientData(regoDir)
	if err != nil {
		return fmt.Errorf("policy: load failed: %w", err)
	}
	if _, err := policy.PrepareSecureClientExact(context.Background(), regoDir); err != nil {
		return fmt.Errorf("policy: compilation failed:\n%w", err)
	}
	fmt.Println("All Rego modules compiled successfully.")
	for _, key := range []string{"config", "actions", "severity_ranking"} {
		if _, ok := data[key]; !ok {
			fmt.Fprintf(os.Stderr, "warning: data.json missing key: %s\n", key)
		}
	}
	fmt.Println("data.json schema: OK")
	return nil
}

var policyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run the Rego unit tests (*_test.rego) without an external opa binary",
	RunE: func(cmd *cobra.Command, _ []string) error {
		regoDir, err := policyCommandRegoDir(cmd)
		if err != nil {
			return err
		}
		verbose, _ := cmd.Flags().GetBool("verbose")

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		results, err := tester.Run(ctx, opaLoaderPath(regoDir))
		if err != nil {
			return fmt.Errorf("policy test: %w", err)
		}
		if len(results) == 0 {
			// The installed policy directories ship no *_test.rego files, so
			// "nothing to test" is the normal answer there, not a failure
			// (GAP-1091).
			fmt.Fprintln(cmd.OutOrStdout(), noRegoTestsMessage(regoDir))
			return nil
		}
		ch := make(chan *tester.Result, len(results))
		failed := false
		for _, r := range results {
			if r.Fail || r.Error != nil {
				failed = true
			}
			ch <- r
		}
		close(ch)
		reporter := tester.PrettyReporter{Output: cmd.OutOrStdout(), Verbose: verbose}
		if err := reporter.Report(ch); err != nil {
			return fmt.Errorf("policy test: report: %w", err)
		}
		if failed {
			return fmt.Errorf("policy test: some Rego tests failed")
		}
		return nil
	},
}

// noRegoTestsMessage explains a Rego directory without unit tests.
func noRegoTestsMessage(regoDir string) string {
	return fmt.Sprintf("No Rego unit tests (*_test.rego) in %s; nothing to run. "+
		"Add <module>_test.rego files next to your policies to test them.", regoDir)
}

// opaLoaderPath keeps OPA from reading a Windows drive letter as its
// "<data-prefix>:<path>" syntax: "C:\x" would load "\x" under data.C and
// fail to find it. A file:// URL has no such prefix and OPA cleans it back
// to "C:/x".
func opaLoaderPath(dir string) string {
	if !strings.Contains(filepath.VolumeName(dir), ":") {
		return dir
	}
	return (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(dir)}).String()
}

// policyCommandRegoDir returns --rego-dir when given, else the configured
// policy layout's Rego directory.
func policyCommandRegoDir(cmd *cobra.Command) (string, error) {
	if cmd != nil {
		if dir, _ := cmd.Flags().GetString("rego-dir"); strings.TrimSpace(dir) != "" {
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				return "", fmt.Errorf("policy: rego directory not found: %s", dir)
			}
			return dir, nil
		}
	}
	paths, err := resolvePolicyPaths()
	if err != nil {
		return "", fmt.Errorf("policy: resolve paths: %w", err)
	}
	return paths.regoDir, nil
}

// ---------------------------------------------------------------------------
// policy show
// ---------------------------------------------------------------------------

var policyShowCmd = &cobra.Command{
	Use:               "show",
	Short:             "Display the admission policy and thresholds compiled from config.yaml",
	Annotations:       map[string]string{secureClientShortAnnotation: "Display the current OPA data.json policy configuration"},
	PersistentPreRunE: policyConfigOnlyPreRunE,
	PersistentPostRun: policyConfigOnlyPostRun,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cfg != nil && cfg.SecureClientIntegration() {
			return showSecureClientPolicy()
		}
		view := map[string]any{"admission": policy.CompileAdmission(cfg)}
		if cfg != nil {
			// The levels the gateway resolves: block_at / alert_at over
			// the rule pack's posture.
			levels := gateway.ConfigThresholds(cfg, "")
			view["guardrail"] = map[string]string{
				"block_at":          levels.Block,
				"alert_at":          levels.Alert,
				"source":            levels.Source,
				"cisco_trust_level": cfg.Guardrail.EffectiveCiscoTrustLevel(),
			}
		}
		out, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

// showSecureClientPolicy is policy show of main, which a Secure Client
// host keeps (issue #1092): the data.json of the Rego directory.
func showSecureClientPolicy() error {
	paths, err := resolvePolicyPaths()
	if err != nil {
		return fmt.Errorf("policy: resolve paths: %w", err)
	}
	data, err := policy.LoadSecureClientData(paths.regoDir)
	if err != nil {
		return fmt.Errorf("policy: load effective data: %w", err)
	}
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

var policyEvaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Dry-run the admission policy for a given input",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if _, windows := managedHostWindowsStandalone(); windows {
			return policyConfigOnlyPreRunE(cmd, args)
		}
		if _, unix := managedHostUnixRecord(nil); unix {
			return policyConfigOnlyPreRunE(cmd, args)
		}
		return rootPersistentPreRunE(cmd, args)
	},
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

		secureClient := cfg != nil && cfg.SecureClientIntegration()
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: targetName,
			Path:       "/dry-run",
		}
		if !secureClient {
			input.BlockList, input.AllowList = policy.AssetPolicyListsFor(cfg, config.AssetPolicyInput{
				TargetType: targetType, Name: targetName, SourcePath: "/dry-run",
			})
			input.Admission = policy.AdmissionFor(policy.CompileAdmission(cfg), targetType)
		}

		if severity != "" {
			input.ScanResult = &policy.ScanResultInput{
				MaxSeverity:   severity,
				TotalFindings: findings,
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// The managed packages ship no Rego: the config-driven twin the
		// gateway falls back to decides, as it does there. Secure Client
		// keeps the engine error of main (issue #1092).
		var out *policy.AdmissionOutput
		var engine *policy.Engine
		var secureClientPrepared *policy.Prepared
		if secureClient {
			secureClientPrepared, err = policy.PrepareSecureClientExact(ctx, paths.regoDir)
		} else {
			engine, err = policy.NewExact(paths.regoDir)
		}
		switch {
		case !secureClient && (errors.Is(err, policy.ErrNoModules) || errors.Is(err, fs.ErrNotExist)):
			out = policy.EvaluateAdmissionFallback(input)
		case err != nil:
			return err
		default:
			if secureClient {
				out, err = secureClientPrepared.EvaluateAdmission(ctx, input)
			} else {
				out, err = engine.Evaluate(ctx, input)
			}
			if err != nil {
				return fmt.Errorf("evaluation failed: %w", err)
			}
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
	Short: "Tell the running gateway to reload OPA policies",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := managedStandardUserGatewayRefusal(); err != nil {
			return err
		}
		return rootPersistentPreRunE(cmd, args)
	},
	RunE: func(_ *cobra.Command, _ []string) error {
		port := 18790
		bind := "127.0.0.1"
		if cfg != nil {
			port = cfg.Gateway.APIPort
			if cfg.Gateway.APIBind != "" {
				bind = cfg.Gateway.APIBind
			}
		}

		// The reload carries the gateway token: never to a listener that is
		// not this account's gateway (GAP-1563).
		if problem := foreignGatewayListener(cfg); problem != "" {
			return fmt.Errorf("policy reload: %s; the gateway token was not sent. %s", problem, foreignGatewayListenerFix(cfg))
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
		if cfg != nil && cfg.SecureClientIntegration() {
			return printSecureClientPolicyReload(resp.StatusCode, body)
		}
		if resp.StatusCode != http.StatusOK {
			return policyReloadError(resp.StatusCode, body)
		}

		fmt.Println(policyReloadMessage(body))
		return nil
	},
}

// printSecureClientPolicyReload is the policy reload output of main, which a
// Secure Client host keeps (issue #1092): a refused reload shows the HTTP
// status and the body, a successful one the indented JSON answer.
func printSecureClientPolicyReload(status int, body []byte) error {
	if status != http.StatusOK {
		return fmt.Errorf("reload failed (HTTP %d): %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println(string(body))
	}
	return nil
}

// policyReloadMessage says a successful /policy/reload in one sentence, naming
// the generation and digest that are enforcing now when the gateway reports them.
func policyReloadMessage(body []byte) string {
	var result struct {
		Generation uint64 `json:"generation"`
		Digest     string `json:"digest"`
	}
	if json.Unmarshal(body, &result) != nil || result.Generation == 0 {
		return "Policy reloaded."
	}
	if result.Digest == "" {
		return fmt.Sprintf("Policy reloaded (generation %d).", result.Generation)
	}
	return fmt.Sprintf("Policy reloaded (generation %d, digest %s).", result.Generation, result.Digest)
}

// customPackPinMismatch matches the rebuild error for a custom rule pack whose
// files no longer match its guardrail.custom_packs pin.
var customPackPinMismatch = regexp.MustCompile(`rule pack "([^"]+)": digest (sha256:[0-9a-f]{64}) does not match guardrail\.custom_packs\.`)

// policyReloadError says a refused /policy/reload in plain words: no HTTP
// status, no JSON body and no internal stage names. A rebuild that fails leaves
// the previous policy enforcing; a pin mismatch also names the command that
// pins the pack as it is now.
func policyReloadError(status int, body []byte) error {
	var payload struct {
		Error  string `json:"error"`
		Status string `json:"status"`
	}
	reason := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		reason = payload.Error
	}
	if reason == "" {
		return fmt.Errorf("policy reload failed (HTTP %d)", status)
	}
	reason = strings.TrimPrefix(reason, "reload failed: ")
	reason = strings.TrimPrefix(reason, "config reload rule pack preflight: ")
	if m := customPackPinMismatch.FindStringSubmatch(reason); m != nil {
		key := "guardrail.custom_packs." + m[1] + ".digest"
		return fmt.Errorf("policy reload failed: rule pack %s no longer matches its pin (%s). The previous policy is still enforcing. "+
			"Review the pack, then pin it with: defenseclaw config set %s %s", m[1], key, key, m[2])
	}
	if payload.Status == "failed" {
		return fmt.Errorf("policy reload failed: %s. The previous policy is still enforcing", strings.TrimSuffix(reason, "."))
	}
	return fmt.Errorf("policy reload failed: %s", reason)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type resolvedPolicyPaths struct {
	rootDir string
	regoDir string
}

// resolvePolicyPaths resolves one immutable layout for every local policy
// command. Current installations use <policy-root>/rego; releases through
// 0.3.x used the flat policy root. Canonical modules always win, so a stale
// flat copy cannot shadow them.
func resolvePolicyPaths() (resolvedPolicyPaths, error) {
	root, err := resolvePolicyRoot()
	if err != nil {
		return resolvedPolicyPaths{}, err
	}

	nestedDir, err := resolveContainedPolicyPath(root, filepath.Join(root, "rego"))
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("resolve canonical Rego directory: %w", err)
	}
	nestedModules, err := policyDirectoryHasRego(root, nestedDir)
	if err != nil {
		return resolvedPolicyPaths{}, fmt.Errorf("inspect canonical Rego directory: %w", err)
	}

	// Secure Client still reads legacy data.json; a canonical data file
	// selects that layout even when it has no Rego modules.
	if cfg != nil && cfg.SecureClientIntegration() {
		nestedData, err := resolveContainedPolicyPath(root, filepath.Join(nestedDir, "data.json"))
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("resolve canonical policy data: %w", err)
		}
		dataExists, err := policyDataFileExists(nestedData)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect canonical policy data: %w", err)
		}
		nestedModules = nestedModules || dataExists
	}
	paths := resolvedPolicyPaths{rootDir: root, regoDir: nestedDir}
	if !nestedModules {
		flatModules, err := policyDirectoryHasRego(root, root)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect legacy Rego directory: %w", err)
		}
		if flatModules {
			paths.regoDir = root
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
		deeperModules, err := policyDirectoryHasRego(root, deeperDir)
		if err != nil {
			return resolvedPolicyPaths{}, fmt.Errorf("inspect nested Rego directory: %w", err)
		}
		if deeperModules {
			return resolvedPolicyPaths{}, fmt.Errorf("policy root contains an unsupported nested rego/rego layout")
		}
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
