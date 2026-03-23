package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type SkillScanner struct {
	Config config.SkillScannerConfig
}

func NewSkillScanner(cfg config.SkillScannerConfig) *SkillScanner {
	if cfg.Binary == "" {
		cfg.Binary = "skill-scanner"
	}
	return &SkillScanner{Config: cfg}
}

func (s *SkillScanner) Name() string              { return "skill-scanner" }
func (s *SkillScanner) Version() string            { return "1.0.0" }
func (s *SkillScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *SkillScanner) buildArgs(target string) []string {
	args := []string{"scan", "--format", "json"}

	if s.Config.UseLLM {
		args = append(args, "--use-llm")
	}
	if s.Config.UseBehavioral {
		args = append(args, "--use-behavioral")
	}
	if s.Config.EnableMeta {
		args = append(args, "--enable-meta")
	}
	if s.Config.UseTrigger {
		args = append(args, "--use-trigger")
	}
	if s.Config.UseVirusTotal {
		args = append(args, "--use-virustotal")
	}
	if s.Config.UseAIDefense {
		args = append(args, "--use-aidefense")
	}
	if s.Config.LLMProvider != "" {
		args = append(args, "--llm-provider", s.Config.LLMProvider)
	}
	if s.Config.LLMConsensus > 0 {
		args = append(args, "--llm-consensus-runs", strconv.Itoa(s.Config.LLMConsensus))
	}
	if s.Config.Policy != "" {
		args = append(args, "--policy", s.Config.Policy)
	}
	if s.Config.Lenient {
		args = append(args, "--lenient")
	}

	args = append(args, target)
	return args
}

// scanEnv returns the process environment with skill-scanner-specific
// API keys injected from config. Values already present in the
// environment are not overwritten.
func (s *SkillScanner) scanEnv() []string {
	env := os.Environ()

	inject := []struct {
		envVar string
		value  string
	}{
		{"SKILL_SCANNER_LLM_API_KEY", s.Config.LLMAPIKey},
		{"SKILL_SCANNER_LLM_MODEL", s.Config.LLMModel},
		{"VIRUSTOTAL_API_KEY", s.Config.VirusTotalKey},
		{"AI_DEFENSE_API_KEY", s.Config.AIDefenseKey},
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

	return env
}

func (s *SkillScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	args := s.buildArgs(target)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Duration:  duration,
	}

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv pip install cisco-ai-skill-scanner", s.Name(), s.Config.Binary)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderr.String())
		}
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseSkillOutput(stdout.Bytes())
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
		}
		result.Findings = findings
	}

	return result, nil
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
}

func parseSkillOutput(data []byte) ([]Finding, error) {
	var out skillOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "skill-scanner",
		})
	}
	return findings, nil
}
