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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// liteLLMModel returns the model string shaped for LiteLLM /
// provider-native routers. LiteLLM accepts “"provider/model-id"“
// directly — the same shape DefenseClaw uses in config. A bare
// “llm.Model“ with a separate “llm.Provider“ gets stitched into
// “"<provider>/<model>"“. Empty models are passed through unchanged
// (the caller should handle that case).
func liteLLMModel(llm config.LLMConfig) string {
	model := llm.Model
	if model != "" && llm.Provider != "" && !strings.Contains(model, "/") {
		return llm.Provider + "/" + model
	}
	return model
}

// extractJSON finds the first top-level JSON object in data.
// Scanner CLIs sometimes print progress text to stdout before the JSON;
// this isolates the `{...}` payload so json.Unmarshal succeeds.
// extractJSON locates the first balanced JSON object in data by tracking
// brace depth while skipping string literals.
func extractJSON(data []byte) []byte {
	start := bytes.IndexByte(data, '{')
	if start < 0 {
		return data
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(data); i++ {
		b := data[i]
		if escaped {
			escaped = false
			continue
		}
		if b == '\\' && inString {
			escaped = true
			continue
		}
		if b == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch b {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return data[start : i+1]
			}
		}
	}
	return data
}

// SkillScanner shells out to the Python “cisco-ai-skill-scanner“ CLI.
//
// Everything the scanner does is derived from config: the policy, the judge
// (the resolved “llm:“ block, Config.ResolveLLM("scanners.skill")), the
// optional analyzers and the environment. The process environment is an
// allowlist, so shell variables such as “SKILL_SCANNER_LLM_MODEL“ never
// change a scan. DefenseClaw never passes “--fail-on-severity“: the gate is
// applied to the JSON findings by admission (fail_on_severity), and any
// non-zero exit is a scan error.
type SkillScanner struct {
	Config         config.SkillScannerConfig
	LLM            config.LLMConfig
	CiscoAIDefense config.CiscoAIDefenseConfig
}

// NewSkillScannerFromLLM constructs a scanner from the resolved judge LLM
// (rootCfg.ResolveLLM("scanners.skill")).
func NewSkillScannerFromLLM(cfg config.SkillScannerConfig, llm config.LLMConfig, aid config.CiscoAIDefenseConfig) *SkillScanner {
	if cfg.Binary == "" {
		cfg.Binary = "skill-scanner"
	}
	cfg.Binary = resolveScannerRuntime(cfg.Binary, "skill-scanner", "skill-scanner.exe")
	return &SkillScanner{
		Config:         cfg,
		LLM:            llm,
		CiscoAIDefense: aid,
	}
}

func (s *SkillScanner) Name() string               { return "skill-scanner" }
func (s *SkillScanner) Version() string            { return "1.0.0" }
func (s *SkillScanner) SupportedTargets() []string { return []string{"skill"} }

// skillJudge is the scanner's view of the judge LLM.
type skillJudge struct {
	model      string
	provider   string // --llm-provider; "" lets the model prefix route
	apiKey     string
	baseURL    string
	apiVersion string
	awsRegion  string
}

// openAICompatibleProviders are DefenseClaw provider names served through
// the scanner's openai-compatible route (a base URL and a served model name).
var openAICompatibleProviders = map[string]bool{
	"openai-compatible": true, "custom-openai": true, "vllm": true,
	"lm_studio": true, "lmstudio": true, "local": true,
}

// judge maps the resolved LLM onto the scanner's LLM settings. The scanner's
// --llm-provider only knows anthropic, openai and openai-compatible; every
// other provider (bedrock, vertex_ai, azure, gemini, ollama, ...) routes by
// its LiteLLM model prefix. ok is false when no judge can run: no model, or
// a provider that needs a key and has none (keyless Bedrock and local
// servers are fine). The scanner exits 2 when a requested judge cannot
// start, so an unusable judge is not requested.
func (s *SkillScanner) judge() (skillJudge, bool) {
	llm := s.LLM
	j := skillJudge{model: liteLLMModel(llm), apiKey: llm.ResolvedAPIKey(), baseURL: strings.TrimSpace(llm.RequestBaseURL())}
	if j.model == "" {
		return j, false
	}
	prefix := llm.ProviderPrefix()
	switch {
	case prefix == "anthropic" || prefix == "openai":
		j.provider = prefix
	case openAICompatibleProviders[prefix]:
		j.provider = "openai-compatible"
		// The server knows the model by its served name.
		j.model = strings.TrimPrefix(j.model, prefix+"/")
	}
	if llm.Azure != nil {
		if j.baseURL == "" {
			j.baseURL = strings.TrimSpace(llm.Azure.Endpoint)
		}
		j.apiVersion = strings.TrimSpace(llm.Azure.APIVersion)
	}
	if llm.Bedrock != nil && strings.TrimSpace(llm.Bedrock.Region) != "" {
		j.awsRegion = strings.TrimSpace(llm.Bedrock.Region)
	} else if strings.HasPrefix(strings.ToLower(j.model), "bedrock") {
		j.awsRegion = strings.TrimSpace(llm.Region)
	}
	switch {
	case j.apiKey != "":
	case llm.IsLocalProvider():
		// The openai-compatible route needs a key; local servers ignore it.
		j.apiKey = "local-no-key"
	case strings.HasPrefix(strings.ToLower(j.model), "bedrock"):
		// Keyless Bedrock signs with the AWS credential chain.
	default:
		return j, false
	}
	return j, true
}

// commandArgs is the scanner command line: buildArgs, led by the tool name
// when the binary is the embedded scanner runtime.
func (s *SkillScanner) commandArgs(target, policy string) []string {
	args := s.buildArgs(target, policy)
	if usesScannerRuntime(s.Config.Binary) {
		return append([]string{"skill-scanner"}, args...)
	}
	return args
}

func (s *SkillScanner) buildArgs(target, policy string) []string {
	args := []string{"scan", "--format", "json", "--policy", policy}

	judged := false
	if s.Config.UseLLM {
		if j, ok := s.judge(); ok {
			judged = true
			args = append(args, "--use-llm")
			if j.provider != "" {
				args = append(args, "--llm-provider", j.provider)
			}
			if s.Config.LLMConsensus > 0 {
				args = append(args, "--llm-consensus-runs", strconv.Itoa(s.Config.LLMConsensus))
			}
		}
	}
	if s.Config.UseBehavioral {
		args = append(args, "--use-behavioral")
	}
	// The meta-analyzer needs the judge: without one skill-scanner exits 2
	// ("Meta-Analyzer LLM API key not configured"), which fails the scan
	// closed. Python runs meta under the same condition.
	if s.Config.EnableMeta && judged {
		args = append(args, "--enable-meta")
	}
	if s.Config.UseTrigger {
		args = append(args, "--use-trigger")
	}
	if s.Config.Analyzers.VirusTotal.Enabled {
		args = append(args, "--use-virustotal")
		if s.Config.Analyzers.VirusTotal.UploadFiles {
			args = append(args, "--vt-upload-files")
		}
	}
	if s.Config.Analyzers.AIDefense.Enabled {
		args = append(args, "--use-aidefense")
	}
	if s.Config.Analyzers.OSV.Enabled {
		args = append(args, "--use-osv")
	}
	if s.Config.Lenient {
		args = append(args, "--lenient")
	}

	args = append(args, target)
	return args
}

// skillScannerEnvPassthrough are the process variables a scan inherits:
// what Python needs to start on each OS, proxy and CA settings, and the
// cloud credential chains LiteLLM signs keyless judges with. Names compare
// case-insensitively (Windows).
var skillScannerEnvPassthrough = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "USERPROFILE": true,
	"TMPDIR": true, "TMP": true, "TEMP": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true,
	"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true, "SYSTEMDRIVE": true,
	// Python's platform.machine() reads these on Windows; without them
	// skill-scanner's CEL helper saw "win32/" and refused to start.
	"PROCESSOR_ARCHITECTURE": true, "PROCESSOR_ARCHITEW6432": true, "NUMBER_OF_PROCESSORS": true, "OS": true,
	"APPDATA": true, "LOCALAPPDATA": true, "PROGRAMDATA": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "REQUESTS_CA_BUNDLE": true, "CURL_CA_BUNDLE": true,
	"GOOGLE_APPLICATION_CREDENTIALS": true, "GOOGLE_CLOUD_PROJECT": true,
	"VERTEXAI_PROJECT": true, "VERTEXAI_LOCATION": true,
}

var skillScannerEnvPassthroughPrefixes = []string{"AWS_", "AZURE_"}

// scanEnv builds the scanner environment from config: the allowlisted
// process variables plus the derived scanner settings. Nothing else from
// the gateway's environment (SKILL_SCANNER_*, VIRUSTOTAL_*, AI_DEFENSE_*,
// ENABLE_*_ANALYZER, ...) reaches the scanner.
func (s *SkillScanner) scanEnv() []string {
	env := make([]string, 0, 32)
	derived := map[string]string{"NO_COLOR": "1", "TERM": "dumb"}
	if s.Config.UseLLM {
		if j, ok := s.judge(); ok {
			derived["SKILL_SCANNER_LLM_MODEL"] = j.model
			derived["SKILL_SCANNER_LLM_API_KEY"] = j.apiKey
			derived["SKILL_SCANNER_LLM_BASE_URL"] = j.baseURL
			derived["SKILL_SCANNER_LLM_API_VERSION"] = j.apiVersion
			derived["AWS_REGION"] = j.awsRegion
		}
	}
	if s.Config.Analyzers.VirusTotal.Enabled {
		derived["VIRUSTOTAL_API_KEY"] = s.Config.ResolvedVirusTotalKey()
	}
	if s.Config.Analyzers.AIDefense.Enabled {
		derived["AI_DEFENSE_API_KEY"] = s.CiscoAIDefense.ResolvedAPIKey()
		derived["AI_DEFENSE_API_URL"] = strings.TrimSpace(s.CiscoAIDefense.Endpoint)
	}
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		upper := strings.ToUpper(name)
		if v, set := derived[upper]; set && v != "" {
			continue // config wins over the inherited value
		}
		if skillScannerEnvPassthrough[upper] || hasAnyPrefix(upper, skillScannerEnvPassthroughPrefixes) {
			env = append(env, kv)
		}
	}
	for name, value := range derived {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// policyArg is the --policy value. A custom policy is copied to a private
// temp file only after its sha256 matches policy_file.digest, so the
// scanner reads exactly the verified bytes; cleanup removes the copy.
func (s *SkillScanner) policyArg() (string, func(), error) {
	policy := s.Config.EffectivePolicy()
	if policy != config.SkillScannerPolicyCustom {
		return policy, func() {}, nil
	}
	data, err := s.Config.PolicyFile.ReadVerified()
	if err != nil {
		return "", func() {}, fmt.Errorf("scanner: skill-scanner custom policy refused: %w", err)
	}
	dir, err := os.MkdirTemp("", "dc-skill-policy-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (s *SkillScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	exitCode := 0
	var scanErr error

	result := &ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		TargetType: InferTargetType(s.Name()),
	}
	if s.Config.UseLLM {
		if j, ok := s.judge(); ok {
			result.JudgeModel = j.model
		}
	}

	policy, cleanup, err := s.policyArg()
	defer cleanup()
	if err != nil {
		// Fail closed: a custom policy that does not match its digest is a
		// scan error, never a scan with some other policy.
		result.Duration = time.Since(start)
		result.ScanError = err.Error()
		result.ExitCode = -1
		return result, err
	}

	scanPath, unstage, err := stageUTF16Skill(target)
	defer unstage()
	if err != nil {
		result.Duration = time.Since(start)
		result.ScanError = err.Error()
		result.ExitCode = -1
		return result, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.Config.ScanTimeoutSeconds())*time.Second)
	defer cancel()
	cmd := processutil.CommandContext(ctx, s.Config.Binary, s.commandArgs(scanPath, policy)...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = processutil.RunTree(cmd)
	result.Duration = time.Since(start)
	stderrStr := stderr.String()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(err, exec.ErrNotFound) {
			scanErr = fmt.Errorf("scanner: %s not found at %q — repair the managed DefenseClaw installation; source checkouts: uv sync", s.Name(), s.Config.Binary)
			return nil, scanErr
		}
		if stdout.Len() == 0 {
			scanErr = fmt.Errorf("scanner: %s exited %d: %s", s.Name(), exitCode, scannerFailureText(stderrStr))
			return nil, scanErr
		}
	}

	result.ExitCode = exitCode
	if exitCode != 0 {
		result.ScanError = stderrStr
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseSkillOutput(stdout.Bytes(), scanPath)
		if parseErr != nil {
			scanErr = fmt.Errorf("scanner: failed to parse %s output: %w (stderr=%s)", s.Name(), parseErr, stderrStr)
			return nil, scanErr
		}
		result.Findings = findings
	}

	// Fail closed on any non-zero exit even when stdout parsed: exit 2 is
	// an LLM/behavioral/meta configuration error, and DefenseClaw never
	// passes --fail-on-severity, so there is no "findings" exit to accept.
	if exitCode != 0 {
		scanErr = fmt.Errorf("scanner %s exited %d (stderr=%s)", s.Name(), exitCode, scannerFailureText(stderrStr))
		return result, scanErr
	}

	return result, nil
}

// RuleLLMAnalysisFailed is the INFO finding skill-scanner reports when its
// LLM judge started but did not answer (an outage, blocked egress, a model
// error); the scan then finished with the deterministic analyzers only.
const RuleLLMAnalysisFailed = "LLM_ANALYSIS_FAILED"

// ErrJudgeDidNotRun marks a skill scan whose LLM judge did not run.
var ErrJudgeDidNotRun = errors.New("the LLM judge did not run, so the scan is incomplete")

// JudgeFailure returns an ErrJudgeDidNotRun error when result carries the
// scanner's LLM_ANALYSIS_FAILED finding, nil otherwise. The install watcher
// fails such a scan closed, as skill-scanner.mdx promises for a judge that
// cannot run (GAP-0376); the INFO finding alone read as a clean scan.
func JudgeFailure(result *ScanResult) error {
	if result == nil {
		return nil
	}
	for _, f := range result.Findings {
		if f.RuleID != RuleLLMAnalysisFailed {
			continue
		}
		detail := strings.Join(strings.Fields(f.Description), " ")
		if len(detail) > 240 {
			detail = detail[:240] + "..."
		}
		if detail == "" {
			return ErrJudgeDidNotRun
		}
		return fmt.Errorf("%w: %s", ErrJudgeDidNotRun, detail)
	}
	return nil
}

type skillOutput struct {
	Findings []skillFinding `json:"findings"`
}

type skillFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Line        int    `json:"line"`
	// The upstream skill-scanner JSON names the file and line as file_path
	// and line_number (GAP-1848); location and line are the older names.
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	Snippet    string `json:"snippet"`
}

// parseSkillOutput reads the scanner JSON; target is the scanned skill
// directory, used to correct SKILL.md line numbers ("" skips that).
func parseSkillOutput(data []byte, target string) ([]Finding, error) {
	clean := extractJSON(ansiRe.ReplaceAll(data, nil))
	var out skillOutput
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		line := f.Line
		if line <= 0 {
			line = f.LineNumber
		}
		if f.Location == "" && f.FilePath != "" {
			// Same "helper.py:6" form as the Python skill scan, so watcher
			// and path-scan alerts name the file and line alike (GAP-1848).
			f.Location = f.FilePath
			if line > 0 {
				line = skillSnippetLine(target, f.FilePath, line, f.Snippet)
				f.Location = fmt.Sprintf("%s:%d", f.FilePath, line)
			}
		}
		var ln *int
		if line > 0 {
			v := line
			ln = &v
		}
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "skill-scanner",
			RuleID:      f.RuleID,
			Category:    f.Category,
			LineNumber:  ln,
		})
	}
	return findings, nil
}

// skillSnippetLine is the file line that holds snippet when the scanner's
// line is off: the SDK counts SKILL.md lines from the end of the front
// matter (GAP-1599, the same correction as the Python skill scan). It keeps
// line when that line already holds the snippet or the snippet is not found.
func skillSnippetLine(target, filePath string, line int, snippet string) int {
	first := ""
	for _, text := range strings.Split(snippet, "\n") {
		if text = strings.TrimSpace(text); text != "" {
			first = text
			break
		}
	}
	if first == "" || target == "" {
		return line
	}
	path := filePath
	if !filepath.IsAbs(path) {
		path = filepath.Join(target, filePath)
	}
	if info, err := os.Stat(path); err != nil || info.Size() > 2_000_000 {
		return line
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return line
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if line <= len(lines) && strings.Contains(lines[line-1], first) {
		return line
	}
	for i, text := range lines {
		if strings.Contains(text, first) {
			return i + 1
		}
	}
	return line
}
