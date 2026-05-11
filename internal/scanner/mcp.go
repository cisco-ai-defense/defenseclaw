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

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// mcpScanTargetLooksLikeURL returns true when “target“ parses as a
// remote URL (http/https/ws/wss/sse). Local paths and stdio targets
// fall through unchanged so the scanner still accepts them.
func mcpScanTargetLooksLikeURL(target string) bool {
	if target == "" {
		return false
	}
	lower := strings.ToLower(target)
	for _, scheme := range []string{"http://", "https://", "ws://", "wss://", "sse://"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

// validateMCPScanTargetURL refuses MCP scan URLs that point at
// loopback / private / link-local / cloud metadata destinations, or
// that embed inline credentials. The check is opt-out via
// DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS=1 for local development only.
func validateMCPScanTargetURL(target string) error {
	if os.Getenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS") == "1" {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid MCP scan target URL: %w", err)
	}
	if u.User != nil {
		return errors.New("MCP scan target URL must not contain inline credentials")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("MCP scan target URL has empty host")
	}
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" ||
		lowerHost == "ip6-localhost" ||
		lowerHost == "ip6-loopback" ||
		strings.HasSuffix(lowerHost, ".localhost") {
		return fmt.Errorf("MCP scan target %q points at loopback host", host)
	}
	if lowerHost == "metadata.google.internal" {
		return fmt.Errorf("MCP scan target %q points at cloud metadata host", host)
	}
	if literal := net.ParseIP(host); literal != nil {
		if literal.IsLoopback() ||
			literal.IsPrivate() ||
			literal.IsLinkLocalUnicast() ||
			literal.IsLinkLocalMulticast() ||
			literal.IsUnspecified() ||
			literal.IsMulticast() {
			return fmt.Errorf("MCP scan target IP %s is loopback/private/link-local/multicast", literal)
		}
		// AWS / Oracle / DO IMDS literals.
		if literal.String() == "169.254.169.254" || literal.String() == "fd00:ec2::254" {
			return fmt.Errorf("MCP scan target %s is a cloud metadata endpoint", literal)
		}
		return nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		// DNS failure is treated as fatal here: an unresolvable host
		// would be revalidated at dial time and we cannot rely on the
		// downstream scanner to do that.
		return fmt.Errorf("MCP scan target %q does not resolve: %w", host, err)
	}
	for _, ip := range addrs {
		if ip.IsLoopback() ||
			ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() ||
			ip.IsMulticast() ||
			ip.String() == "169.254.169.254" ||
			ip.String() == "fd00:ec2::254" {
			return fmt.Errorf("MCP scan target %q resolves to private/loopback IP %s", host, ip)
		}
	}
	return nil
}

// MCPScanner shells out to the Python “cisco-ai-mcp-scanner“ CLI.
// Mirrors “SkillScanner“: the LLM-facing surface is driven by the
// unified “config.LLMConfig“ resolved at “scanners.mcp“, with the
// legacy “InspectLLMConfig“ kept only to preserve the old
// “NewMCPScanner“ signature for existing callers/tests.
type MCPScanner struct {
	Config         config.MCPScannerConfig
	LLM            config.LLMConfig
	InspectLLM     config.InspectLLMConfig // Deprecated: populated only for back-compat; do not read.
	CiscoAIDefense config.CiscoAIDefenseConfig
}

// NewMCPScanner is the back-compat constructor. Translates the legacy
// “InspectLLMConfig“ shape into the unified “LLMConfig“ internally
// so everything downstream only deals with one structure. Prefer
// “NewMCPScannerFromLLM“ in new code.
func NewMCPScanner(cfg config.MCPScannerConfig, llm config.InspectLLMConfig, aid config.CiscoAIDefenseConfig) *MCPScanner {
	if cfg.Binary == "" {
		cfg.Binary = "mcp-scanner"
	}
	return &MCPScanner{
		Config:         cfg,
		LLM:            inspectToLLM(llm),
		InspectLLM:     llm,
		CiscoAIDefense: aid,
	}
}

// NewMCPScannerFromLLM constructs a scanner directly from the unified
// LLM config. Call sites should resolve once via
// “rootCfg.ResolveLLM("scanners.mcp")“ and pass the result here.
func NewMCPScannerFromLLM(cfg config.MCPScannerConfig, llm config.LLMConfig, aid config.CiscoAIDefenseConfig) *MCPScanner {
	if cfg.Binary == "" {
		cfg.Binary = "mcp-scanner"
	}
	return &MCPScanner{
		Config:         cfg,
		LLM:            llm,
		CiscoAIDefense: aid,
	}
}

func (s *MCPScanner) Name() string               { return "mcp-scanner" }
func (s *MCPScanner) Version() string            { return "1.0.0" }
func (s *MCPScanner) SupportedTargets() []string { return []string{"mcp"} }

func (s *MCPScanner) buildArgs(target string) []string {
	args := []string{"scan", "--format", "json"}

	if s.Config.Analyzers != "" {
		args = append(args, "--analyzers", s.Config.Analyzers)
	}
	if s.Config.ScanPrompts {
		args = append(args, "--scan-prompts")
	}
	if s.Config.ScanResources {
		args = append(args, "--scan-resources")
	}
	if s.Config.ScanInstructions {
		args = append(args, "--scan-instructions")
	}

	args = append(args, target)
	return args
}

func (s *MCPScanner) scanEnv() []string {
	env := os.Environ()

	inject := []struct {
		envVar string
		value  string
	}{
		{"MCP_SCANNER_API_KEY", s.CiscoAIDefense.ResolvedAPIKey()},
		{"MCP_SCANNER_ENDPOINT", s.CiscoAIDefense.Endpoint},
		// mcp-scanner-specific env vars. The Python scanner reads
		// these directly; ``liteLLMModel`` yields the LiteLLM-shaped
		// ``provider/model`` string when a bare model + separate
		// provider were configured, matching what the unified
		// ``Config.ResolveLLM`` produces.
		{"MCP_SCANNER_LLM_API_KEY", s.LLM.ResolvedAPIKey()},
		{"MCP_SCANNER_LLM_MODEL", liteLLMModel(s.LLM)},
		{"MCP_SCANNER_LLM_BASE_URL", s.LLM.BaseURL},
	}

	existing := make(map[string]bool)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				existing[e[:i]] = true
				break
			}
		}
	}

	for _, kv := range inject {
		if kv.value != "" && !existing[kv.envVar] {
			env = append(env, kv.envVar+"="+kv.value)
		}
	}

	if !existing["NO_COLOR"] {
		env = append(env, "NO_COLOR=1")
	}
	if !existing["TERM"] {
		env = append(env, "TERM=dumb")
	}

	return env
}

func (s *MCPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	ctx, sp := BeginScanSpan(ctx, s.Name(), target, InferTargetType(s.Name()), AgentIdentity{})
	exitCode := 0
	var scanErr error
	var result *ScanResult
	defer func() {
		FinishScanSpan(sp, result, exitCode, scanErr)
	}()

	// ("MCP scan target is passed to a remote-
	// capable scanner without URL guarding"): mcp-scanner accepts
	// either a local path or a URL. When it's a URL, it dials the
	// host from the sidecar's network context. Apply the same
	// outbound-URL guard that webhook validation and the proxy use:
	// reject loopback, private, link-local, metadata, and
	// userinfo-bearing URLs unless the caller opts in via
	// DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS=1 (only useful for local
	// dev; never enable in production).
	if mcpScanTargetLooksLikeURL(target) {
		if err := validateMCPScanTargetURL(target); err != nil {
			result = &ScanResult{
				Scanner:   s.Name(),
				Target:    target,
				Timestamp: start,
				ScanError: err.Error(),
				ExitCode:  -1,
			}
			scanErr = err
			exitCode = -1
			return result, scanErr
		}
	}

	args := s.buildArgs(target)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	stderrStr := stderr.String()

	result = &ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		Duration:   duration,
		TargetType: InferTargetType(s.Name()),
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(err, exec.ErrNotFound) {
			scanErr = fmt.Errorf("scanner: %s not found at %q — install with: uv tool install cisco-ai-mcp-scanner", s.Name(), s.Config.Binary)
			return nil, scanErr
		}
		if exitCode != 0 {
			EmitSubprocessExitFromContext(ctx, s.Config.Binary, exitCode, stderrStr)
		}
		if stdout.Len() == 0 {
			scanErr = fmt.Errorf("scanner: %s failed: %s", s.Name(), stderrStr)
			return nil, scanErr
		}
	}

	result.ExitCode = exitCode
	if exitCode != 0 {
		result.ScanError = stderrStr
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseMCPOutput(stdout.Bytes())
		if parseErr != nil {
			scanErr = fmt.Errorf("scanner: failed to parse %s output: %w (stderr=%s)", s.Name(), parseErr, stderrStr)
			return nil, scanErr
		}
		result.Findings = findings
	}

	// hardening (S2.scanners): fail closed on any non-zero
	// scanner exit, even when stdout was parseable. Previously a
	// scanner that exited non-zero with `{"findings":[]}` was treated
	// as a clean scan because admission callers branched only on the
	// returned error. The returned result is preserved so callers can
	// observe ExitCode/ScanError/partial findings for diagnostics,
	// but the non-nil error guarantees fail-closed behaviour in the
	// watcher and REST scan handlers. See finding "Non-zero MCP
	// scanner exits can be treated as successful scans".
	if exitCode != 0 {
		scanErr = fmt.Errorf("scanner %s exited %d (stderr=%s)", s.Name(), exitCode, stderrStr)
		return result, scanErr
	}

	return result, nil
}

type mcpOutput struct {
	Findings []mcpFinding `json:"findings"`
}

type mcpFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Line        int    `json:"line"`
}

func parseMCPOutput(data []byte) ([]Finding, error) {
	clean := extractJSON(ansiRe.ReplaceAll(data, nil))
	var out mcpOutput
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		var ln *int
		if f.Line > 0 {
			v := f.Line
			ln = &v
		}
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "mcp-scanner",
			RuleID:      f.RuleID,
			Category:    f.Category,
			LineNumber:  ln,
		})
	}
	return findings, nil
}
