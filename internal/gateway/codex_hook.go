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

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type codexHookRequest struct {
	HookEventName        string                 `json:"hook_event_name"`
	SessionID            string                 `json:"session_id,omitempty"`
	TurnID               string                 `json:"turn_id,omitempty"`
	TranscriptPath       string                 `json:"transcript_path,omitempty"`
	CWD                  string                 `json:"cwd,omitempty"`
	Model                string                 `json:"model,omitempty"`
	Source               string                 `json:"source,omitempty"`
	ToolName             string                 `json:"tool_name,omitempty"`
	ToolUseID            string                 `json:"tool_use_id,omitempty"`
	ToolInput            map[string]interface{} `json:"tool_input,omitempty"`
	ToolResponse         interface{}            `json:"tool_response,omitempty"`
	Prompt               string                 `json:"prompt,omitempty"`
	StopHookActive       bool                   `json:"stop_hook_active,omitempty"`
	LastAssistantMessage string                 `json:"last_assistant_message,omitempty"`
	ScanComponents       bool                   `json:"scan_components,omitempty"`
	Bridge               map[string]interface{} `json:"bridge,omitempty"`
}

type codexHookResponse struct {
	Action            string                 `json:"action"`
	RawAction         string                 `json:"raw_action,omitempty"`
	Severity          string                 `json:"severity"`
	Reason            string                 `json:"reason,omitempty"`
	Findings          []string               `json:"findings,omitempty"`
	Mode              string                 `json:"mode"`
	WouldBlock        bool                   `json:"would_block"`
	AdditionalContext string                 `json:"additional_context,omitempty"`
	CodexOutput       map[string]interface{} `json:"codex_output,omitempty"`
}

func (a *APIServer) handleCodexHook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req codexHookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.HookEventName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook_event_name is required"})
		return
	}

	t0 := time.Now()
	resp := a.evaluateCodexHook(r.Context(), req)
	elapsed := time.Since(t0)

	if a.health != nil {
		a.health.RecordConnectorRequest()
		if resp.Action == "block" {
			a.health.RecordToolBlock()
		}
		if isToolInspectionEvent(req.HookEventName) {
			a.health.RecordToolInspection()
		}
	}

	if a.otel != nil {
		a.otel.RecordInspectEvaluation(r.Context(), "codex:"+req.HookEventName, resp.Action, resp.Severity)
		a.otel.RecordInspectLatency(r.Context(), "codex:"+req.HookEventName, float64(elapsed.Milliseconds()))
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), "codex-hook", req.HookEventName,
			fmt.Sprintf("action=%s severity=%s mode=%s would_block=%v elapsed=%s",
				resp.Action, resp.Severity, resp.Mode, resp.WouldBlock, elapsed))
	}

	a.writeJSON(w, http.StatusOK, resp)
}

func (a *APIServer) evaluateCodexHook(ctx context.Context, req codexHookRequest) codexHookResponse {
	mode := a.codexMode()
	if a.scannerCfg != nil && !a.codexEnabled() {
		return codexResponseFor(req.HookEventName, "allow", "allow", "NONE", "", nil, mode, false)
	}

	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	switch req.HookEventName {
	case "SessionStart":
		if req.ScanComponents || (a.scannerCfg != nil && a.scannerCfg.Codex.ScanOnSessionStart) {
			count := a.scanCodexComponents(ctx, req)
			if count > 0 {
				verdict = &ToolInspectVerdict{
					Action:   "allow",
					Severity: "INFO",
					Reason:   fmt.Sprintf("scanned %d Codex component(s)", count),
					Findings: []string{"CODEX-COMPONENT-SCAN"},
				}
			}
		}
	case "UserPromptSubmit":
		verdict = a.inspectMessageContent(&ToolInspectRequest{
			Tool:      "message",
			Content:   req.Prompt,
			Direction: "prompt",
		})
	case "PreToolUse", "PermissionRequest":
		verdict = a.inspectToolPolicy(&ToolInspectRequest{
			Tool:      codexToolName(req),
			Args:      codexToolArgs(req),
			Direction: "tool_call",
		})
	case "PostToolUse":
		verdict = a.inspectMessageContent(&ToolInspectRequest{
			Tool:      "message",
			Content:   codexToolResponseString(req.ToolResponse),
			Direction: "tool_result",
		})
	case "Stop":
		if !req.StopHookActive && a.scannerCfg != nil && a.scannerCfg.Codex.ScanOnStop {
			verdict = a.scanCodexChangedFiles(ctx, req)
		}
	}

	rawAction := normalizeCodexAction(verdict.Action)
	action := rawAction
	wouldBlock := rawAction == "block" && mode != "action"
	if mode != "action" && rawAction == "block" {
		action = "allow"
	}
	if mode != "action" && rawAction == "alert" {
		action = "allow"
	}
	return codexResponseFor(req.HookEventName, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings, mode, wouldBlock)
}

// codexEnabled mirrors claudeCodeEnabled: selecting the codex connector
// is a sufficient opt-in — the connector's Setup() has already written
// the codex-hook.sh script and (on Codex's side) registered it. An
// explicit codex.enabled flag still wins for operators running codex
// alongside a different selected connector.
func (a *APIServer) codexEnabled() bool {
	if a.scannerCfg == nil {
		return false
	}
	if a.scannerCfg.Codex.Enabled {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(a.scannerCfg.Guardrail.Connector), "codex")
}

func (a *APIServer) codexMode() string {
	mode := "observe"
	if a.scannerCfg != nil {
		mode = strings.TrimSpace(a.scannerCfg.Codex.Mode)
		if mode == "" || mode == "inherit" {
			mode = strings.TrimSpace(a.scannerCfg.Guardrail.Mode)
		}
	}
	if mode != "action" {
		return "observe"
	}
	return mode
}

func codexResponseFor(event, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool) codexHookResponse {
	if severity == "" {
		severity = "NONE"
	}
	if action == "" {
		action = "allow"
	}
	if rawAction == "" {
		rawAction = action
	}
	safeReason := string(redaction.ForSinkReason(reason))
	additional := codexAdditionalContext(rawAction, severity, safeReason, wouldBlock)
	resp := codexHookResponse{
		Action:            action,
		RawAction:         rawAction,
		Severity:          severity,
		Reason:            safeReason,
		Findings:          findings,
		Mode:              mode,
		WouldBlock:        wouldBlock,
		AdditionalContext: additional,
	}
	resp.CodexOutput = codexOutput(event, action, safeReason, additional)
	return resp
}

func codexOutput(event, action, reason, additional string) map[string]interface{} {
	if action == "block" {
		switch event {
		case "PreToolUse":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": reasonOrDefault(reason),
				},
			}
		case "PermissionRequest":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName": "PermissionRequest",
					"decision": map[string]interface{}{
						"behavior": "deny",
						"message":  reasonOrDefault(reason),
					},
				},
			}
		case "UserPromptSubmit", "PostToolUse", "Stop":
			out := map[string]interface{}{
				"decision": "block",
				"reason":   reasonOrDefault(reason),
			}
			if event == "PostToolUse" && additional != "" {
				out["hookSpecificOutput"] = map[string]interface{}{
					"hookEventName":     "PostToolUse",
					"additionalContext": additional,
				}
			}
			return out
		}
	}

	if event == "Stop" {
		return map[string]interface{}{"continue": true}
	}
	if additional == "" {
		return nil
	}
	switch event {
	case "SessionStart":
		return map[string]interface{}{"systemMessage": additional}
	case "UserPromptSubmit", "PostToolUse":
		return map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     event,
				"additionalContext": additional,
			},
		}
	case "PreToolUse":
		return map[string]interface{}{"systemMessage": additional}
	default:
		return nil
	}
}

func codexAdditionalContext(rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s Codex hook finding.", prefix, severity)
	}
	return fmt.Sprintf("%s a %s Codex hook finding: %s", prefix, severity, reason)
}

func reasonOrDefault(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "Blocked by DefenseClaw Codex policy."
	}
	return reason
}

func normalizeCodexAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny":
		return "block"
	case "alert", "warn", "warning":
		return "alert"
	default:
		return "allow"
	}
}

func codexToolName(req codexHookRequest) string {
	if strings.TrimSpace(req.ToolName) != "" {
		return req.ToolName
	}
	return "Bash"
}

func codexToolArgs(req codexHookRequest) json.RawMessage {
	if req.ToolInput == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(req.ToolInput)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func codexToolResponseString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func codexToolResponseLen(v interface{}) int {
	return len(codexToolResponseString(v))
}

func (a *APIServer) scanCodexChangedFiles(ctx context.Context, req codexHookRequest) *ToolInspectVerdict {
	targets := a.codexStopTargets(ctx, req)
	if len(targets) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	maxSeverity := scanner.SeverityInfo
	findings := []string{}
	for _, target := range targets {
		result, err := cg.Scan(ctx, target)
		if err != nil {
			continue
		}
		if a.logger != nil {
			_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
		}
		if result.MaxSeverity() != scanner.SeverityInfo && scanner.CompareSeverity(result.MaxSeverity(), maxSeverity) > 0 {
			maxSeverity = result.MaxSeverity()
		}
		for _, f := range result.Findings {
			findings = append(findings, f.ID)
			if len(findings) >= 20 {
				break
			}
		}
	}
	if len(findings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	action := "alert"
	if maxSeverity == scanner.SeverityCritical || maxSeverity == scanner.SeverityHigh {
		action = "block"
	}
	return &ToolInspectVerdict{
		Action:   action,
		Severity: string(maxSeverity),
		Reason:   fmt.Sprintf("CodeGuard found %d finding(s) in Codex changed files", len(findings)),
		Findings: findings,
	}
}

func (a *APIServer) codexStopTargets(ctx context.Context, req codexHookRequest) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !filepath.IsAbs(p) && req.CWD != "" {
			p = filepath.Join(req.CWD, p)
		}
		if seen[p] {
			return
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			seen[p] = true
			out = append(out, p)
		}
	}
	if a.scannerCfg != nil {
		for _, p := range a.scannerCfg.Codex.ScanPaths {
			add(p)
		}
	}
	changedFiles, gitErr := gitChangedFiles(ctx, req.CWD)
	if gitErr != nil {
		fmt.Fprintf(os.Stderr, "[codex-hook] WARNING: git scan failed: %v — scanning configured paths only\n", gitErr)
	}
	for _, p := range changedFiles {
		add(p)
	}
	if len(out) > 200 {
		return out[:200]
	}
	return out
}

func gitChangedFiles(ctx context.Context, cwd string) ([]string, error) {
	safeCwd, err := validateGitCwd(cwd)
	if err != nil {
		return nil, err
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var errs []error
	files, err := runGitList(cmdCtx, safeCwd, "diff", "--name-only", "--diff-filter=ACMRT", "HEAD", "--")
	if err != nil {
		errs = append(errs, err)
	}
	extra, err := runGitList(cmdCtx, safeCwd, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		errs = append(errs, err)
	}
	files = append(files, extra...)

	if len(errs) > 0 && len(files) == 0 {
		return nil, fmt.Errorf("git commands failed: %v", errs)
	}
	return files, nil
}

// validateGitCwd resolves symlinks and ensures the cwd is a real directory.
// Returns the canonicalized path or an error if validation fails.
func validateGitCwd(cwd string) (string, error) {
	if strings.TrimSpace(cwd) == "" {
		return "", fmt.Errorf("empty cwd")
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve cwd %s: %w", cwd, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("cwd is not a directory: %s", resolved)
	}
	return resolved, nil
}

// safeGitEnv returns environment variables that prevent git from executing
// attacker-controlled config hooks (core.fsmonitor, core.hooksPath, etc.)
// by disabling system/global config and pointing HOME to a safe empty dir.
func safeGitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HOME="+os.TempDir(),
	)
}

func runGitList(ctx context.Context, cwd string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	cmd.Env = safeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v in %s: %w", args, cwd, err)
	}
	lines := strings.Split(string(out), "\n")
	ret := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			ret = append(ret, line)
		}
	}
	return ret, nil
}

func (a *APIServer) scanCodexComponents(ctx context.Context, req codexHookRequest) int {
	if a.scannerCfg == nil {
		return 0
	}
	if !req.ScanComponents && !a.codexComponentScanDue() {
		return 0
	}
	targets := codexComponentTargets(req.CWD)
	count := 0
	for component, paths := range targets {
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if a.scanCodexComponent(ctx, component, p) {
				count++
			}
		}
	}
	return count
}

func (a *APIServer) codexComponentScanDue() bool {
	interval := 60 * time.Minute
	if a.scannerCfg != nil && a.scannerCfg.Codex.ComponentScanIntervalMinutes > 0 {
		interval = time.Duration(a.scannerCfg.Codex.ComponentScanIntervalMinutes) * time.Minute
	}
	a.codexMu.Lock()
	defer a.codexMu.Unlock()
	if !a.codexLastComponentScan.IsZero() && time.Since(a.codexLastComponentScan) < interval {
		return false
	}
	a.codexLastComponentScan = time.Now()
	return true
}

func codexComponentTargets(cwd string) map[string][]string {
	targets := map[string][]string{
		"skill":  {},
		"plugin": {},
		"mcp":    {},
	}

	home, err := os.UserHomeDir()
	if err == nil {
		codexHome := filepath.Join(home, ".codex")
		targets["skill"] = append(targets["skill"], childDirs(filepath.Join(codexHome, "skills"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(codexHome, "plugins"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(codexHome, "plugins", "cache"))...)
		targets["mcp"] = append(targets["mcp"], existingFiles(filepath.Join(codexHome, "config.toml"))...)
	}

	for _, root := range workspaceCodexRoots(cwd) {
		targets["skill"] = append(targets["skill"],
			childDirs(filepath.Join(root, ".codex", "skills"))...)
		targets["skill"] = append(targets["skill"],
			childDirs(filepath.Join(root, "skills"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".codex", "plugins"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".codex", "plugins", "cache"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".agents", "plugins"))...)
		targets["mcp"] = append(targets["mcp"],
			existingFiles(filepath.Join(root, ".codex", "config.toml"), filepath.Join(root, ".mcp.json"))...)
	}
	for k, paths := range targets {
		targets[k] = uniqueExistingPaths(paths)
	}
	return targets
}

func workspaceCodexRoots(cwd string) []string {
	roots := []string{}
	if strings.TrimSpace(cwd) != "" {
		roots = append(roots, cwd)
		if root := gitRootForCWD(cwd); root != "" {
			roots = append(roots, root)
		}
	}
	return uniqueExistingDirs(roots)
}

func gitRootForCWD(cwd string) string {
	safeCwd, err := validateGitCwd(cwd)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	cmd.Dir = safeCwd
	cmd.Env = safeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func childDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			out = append(out, filepath.Join(root, entry.Name()))
		}
	}
	return out
}

func existingFiles(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func uniqueExistingDirs(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func uniqueExistingPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (a *APIServer) scanCodexComponent(ctx context.Context, component, target string) bool {
	if a.scannerCfg == nil {
		return false
	}
	var (
		result *scanner.ScanResult
		err    error
	)
	scanCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	switch component {
	case "skill":
		ss := scanner.NewSkillScannerFromLLM(
			a.scannerCfg.Scanners.SkillScanner,
			a.scannerCfg.ResolveLLM("scanners.skill"),
			a.scannerCfg.CiscoAIDefense,
		)
		result, err = ss.Scan(scanCtx, target)
	case "plugin":
		ps := scanner.NewPluginScanner(a.scannerCfg.Scanners.PluginScanner)
		result, err = ps.Scan(scanCtx, target)
	case "mcp":
		ms := scanner.NewMCPScannerFromLLM(
			a.scannerCfg.Scanners.MCPScanner,
			a.scannerCfg.ResolveLLM("scanners.mcp"),
			a.scannerCfg.CiscoAIDefense,
		)
		result, err = ms.Scan(scanCtx, target)
	}
	if err != nil {
		return false
	}
	if result != nil && a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
	}
	return true
}
