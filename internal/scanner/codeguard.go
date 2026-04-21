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
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type CodeGuardScanner struct {
	RulesDir    string
	customRules []rule
}

func NewCodeGuardScanner(rulesDir string) *CodeGuardScanner {
	if rulesDir == "" {
		home, _ := os.UserHomeDir()
		rulesDir = filepath.Join(home, ".defenseclaw", "codeguard-rules")
	}
	s := &CodeGuardScanner{RulesDir: rulesDir}
	s.customRules = loadCustomRules(rulesDir)
	return s
}

func (s *CodeGuardScanner) allRules() []rule {
	if len(s.customRules) == 0 {
		return builtinRules
	}
	all := make([]rule, 0, len(builtinRules)+len(s.customRules))
	all = append(all, builtinRules...)
	all = append(all, s.customRules...)
	return all
}

func (s *CodeGuardScanner) Name() string              { return "codeguard" }
func (s *CodeGuardScanner) Version() string            { return "1.0.0" }
func (s *CodeGuardScanner) SupportedTargets() []string { return []string{"code"} }

// ScanContent scans an in-memory code string against builtin + custom rules.
// The filename is used for extension-based rule filtering and finding locations.
func (s *CodeGuardScanner) ScanContent(filename, content string) []Finding {
	ext := filepath.Ext(filename)
	var findings []Finding
	rules := s.allRules()

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, r := range rules {
			if len(r.extensions) > 0 && !extMatch(ext, r.extensions) {
				continue
			}
			if r.pattern.MatchString(line) {
				findings = append(findings, Finding{
					ID:          r.id,
					Severity:    r.severity,
					Title:       r.title,
					Description: strings.TrimSpace(line),
					Location:    fmt.Sprintf("%s:%d", filename, lineNum+1),
					Remediation: r.remediation,
					Scanner:     "codeguard",
					Tags:        []string{"codeguard"},
				})
			}
		}
	}

	return findings
}

func (s *CodeGuardScanner) Scan(_ context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: codeguard: %w", err)
	}

	var files []string
	if info.IsDir() {
		files, err = collectCodeFiles(target)
		if err != nil {
			return nil, fmt.Errorf("scanner: codeguard: walk %s: %w", target, err)
		}
	} else {
		files = []string{target}
	}

	rules := s.allRules()
	for _, f := range files {
		findings, err := scanFileWithRules(f, rules)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

var codeExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true,
	".java": true, ".rb": true, ".php": true, ".sh": true,
	".yaml": true, ".yml": true, ".json": true, ".xml": true,
	".c": true, ".cpp": true, ".h": true, ".rs": true,
}

// IsCodeFile reports whether the given file extension is one CodeGuard scans.
func IsCodeFile(ext string) bool {
	return codeExtensions[ext]
}

func collectCodeFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "__pycache__" || base == ".venv" || base == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if codeExtensions[filepath.Ext(path)] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

type rule struct {
	id          string
	severity    Severity
	title       string
	pattern     *regexp.Regexp
	remediation string
	extensions  []string
}

var builtinRules = []rule{
	{
		id:          "CG-CRED-001",
		severity:    SeverityHigh,
		title:       "Hardcoded API key or secret",
		pattern:     regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["'][^\s"']{16,}["']`),
		remediation: "Move credentials to environment variables or a secrets manager",
	},
	{
		id:          "CG-CRED-002",
		severity:    SeverityHigh,
		title:       "AWS access key ID",
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		remediation: "Rotate the key and store in AWS Secrets Manager or environment variables",
	},
	{
		id:          "CG-CRED-003",
		severity:    SeverityCritical,
		title:       "Private key embedded in source",
		pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		remediation: "Remove the private key from source code; use a certificate store or secrets manager",
	},
	{
		id:          "CG-EXEC-001",
		severity:    SeverityHigh,
		title:       "Unsafe command execution",
		pattern:     regexp.MustCompile(`(?i)(os\.system|subprocess\.call|exec\(|child_process\.exec|eval\(|system\()`),
		remediation: "Use parameterized execution or an allowlist of commands",
		extensions:  []string{".py", ".js", ".ts", ".rb", ".php"},
	},
	{
		id:          "CG-EXEC-002",
		severity:    SeverityMedium,
		title:       "Shell=True in subprocess",
		pattern:     regexp.MustCompile(`subprocess\.\w+\(.*shell\s*=\s*True`),
		remediation: "Avoid shell=True; pass arguments as a list",
		extensions:  []string{".py"},
	},
	{
		id:          "CG-NET-001",
		severity:    SeverityMedium,
		title:       "Outbound HTTP request to variable URL",
		pattern:     regexp.MustCompile(`(?i)(requests\.(get|post|put|delete)|urllib\.request\.urlopen|fetch\(|http\.Get)\s*\(`),
		remediation: "Validate and allowlist outbound URLs",
		extensions:  []string{".py", ".js", ".ts", ".go"},
	},
	{
		id:          "CG-DESER-001",
		severity:    SeverityHigh,
		title:       "Unsafe deserialization (pickle/yaml.load)",
		pattern:     regexp.MustCompile(`(?i)(pickle\.loads?|yaml\.load\(|yaml\.unsafe_load)`),
		remediation: "Use yaml.safe_load or json for deserialization; never unpickle untrusted data",
		extensions:  []string{".py"},
	},
	{
		id:          "CG-SQL-001",
		severity:    SeverityHigh,
		title:       "Potential SQL injection (string formatting in query)",
		pattern:     regexp.MustCompile(`(?i)(execute|cursor\.execute|query)\s*\(\s*(f["']|["'].*%s|["'].*\+)`),
		remediation: "Use parameterized queries with bind variables",
		extensions:  []string{".py", ".js", ".ts", ".rb", ".php", ".java"},
	},
	{
		id:          "CG-CRYPTO-001",
		severity:    SeverityMedium,
		title:       "Weak cryptographic algorithm (MD5/SHA1)",
		pattern:     regexp.MustCompile(`(?i)(hashlib\.md5|hashlib\.sha1|MD5\.Create|SHA1\.Create|crypto\.createHash\(['"]md5|crypto\.createHash\(['"]sha1)`),
		remediation: "Use SHA-256 or stronger; see codeguard-0-additional-cryptography",
		extensions:  []string{".py", ".js", ".ts", ".java", ".go", ".rb"},
	},
	{
		id:          "CG-PATH-001",
		severity:    SeverityMedium,
		title:       "Potential path traversal",
		pattern:     regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|path\.join\(.*\.\.|os\.path\.join\(.*\.\.|filepath\.Join\(.*\.\.)`),
		remediation: "Canonicalize paths and validate against an allowed root directory",
	},
}

func scanFileWithRules(path string, rules []rule) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ext := filepath.Ext(path)
	var findings []Finding

	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		for _, r := range rules {
			if len(r.extensions) > 0 && !extMatch(ext, r.extensions) {
				continue
			}
			if r.pattern.MatchString(line) {
				findings = append(findings, Finding{
					ID:          r.id,
					Severity:    r.severity,
					Title:       r.title,
					Description: strings.TrimSpace(line),
					Location:    fmt.Sprintf("%s:%d", path, lineNum),
					Remediation: r.remediation,
					Scanner:     "codeguard",
					Tags:        []string{"codeguard"},
				})
			}
		}
	}

	return findings, sc.Err()
}

// RuleMeta exposes rule metadata for skill generation without leaking the
// compiled regexp.
type RuleMeta struct {
	ID          string
	Severity    Severity
	Title       string
	Remediation string
	Extensions  []string
}

// BuiltinRulesMeta returns metadata for all builtin CodeGuard rules.
func BuiltinRulesMeta() []RuleMeta {
	out := make([]RuleMeta, len(builtinRules))
	for i, r := range builtinRules {
		out[i] = RuleMeta{
			ID:          r.id,
			Severity:    r.severity,
			Title:       r.title,
			Remediation: r.remediation,
			Extensions:  r.extensions,
		}
	}
	return out
}

// customRuleYAML is the schema for a custom CodeGuard rule file.
type customRuleFileYAML struct {
	Version int              `yaml:"version"`
	Rules   []customRuleYAML `yaml:"rules"`
}

type customRuleYAML struct {
	ID          string   `yaml:"id"`
	Severity    string   `yaml:"severity"`
	Title       string   `yaml:"title"`
	Pattern     string   `yaml:"pattern"`
	Remediation string   `yaml:"remediation"`
	Extensions  []string `yaml:"extensions"`
}

func loadCustomRules(dir string) []rule {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var custom []rule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rf customRuleFileYAML
		if err := yaml.Unmarshal(data, &rf); err != nil {
			continue
		}
		for _, cr := range rf.Rules {
			compiled, err := regexp.Compile(cr.Pattern)
			if err != nil {
				continue
			}
			sev := parseSeverity(cr.Severity)
			custom = append(custom, rule{
				id:          cr.ID,
				severity:    sev,
				title:       cr.Title,
				pattern:     compiled,
				remediation: cr.Remediation,
				extensions:  cr.Extensions,
			})
		}
	}
	return custom
}

func parseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func extMatch(ext string, exts []string) bool {
	for _, e := range exts {
		if ext == e {
			return true
		}
	}
	return false
}
