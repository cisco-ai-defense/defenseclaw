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
	"context"
	"fmt"
	"os"
	"regexp"
	"time"
)

// ClawShieldVulnScanner detects common web and agent vulnerabilities across 5 attack categories.
// Ported from github.com/Jason-Cyr/OpenClawSecurity — all logic runs natively in-process.
type ClawShieldVulnScanner struct{}

func NewClawShieldVulnScanner() *ClawShieldVulnScanner { return &ClawShieldVulnScanner{} }

func (s *ClawShieldVulnScanner) Name() string               { return "clawshield-vuln" }
func (s *ClawShieldVulnScanner) Version() string            { return "1.0.0" }
func (s *ClawShieldVulnScanner) SupportedTargets() []string { return []string{"skill", "code"} }

type csVulnRule struct {
	id          string
	category    string
	pattern     *regexp.Regexp
	severity    Severity
	remediation string
}

var csVulnRules = []csVulnRule{
	// SQL Injection
	{id: "CS-VLN-SQLI-UNION", category: "sqli", pattern: regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`), severity: SeverityCritical, remediation: "Use parameterized queries; never interpolate user input into SQL"},
	{id: "CS-VLN-SQLI-TAUT1", category: "sqli", pattern: regexp.MustCompile(`(?i)\bOR\s+['"]?1['"]?\s*=\s*['"]?1['"]?`), severity: SeverityHigh, remediation: "Use parameterized queries with bind variables"},
	{id: "CS-VLN-SQLI-TAUT2", category: "sqli", pattern: regexp.MustCompile(`(?i)\bOR\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]`), severity: SeverityHigh, remediation: "Use parameterized queries with bind variables"},
	{id: "CS-VLN-SQLI-TAUT3", category: "sqli", pattern: regexp.MustCompile(`(?i)\bOR\s+true\b`), severity: SeverityHigh, remediation: "Use parameterized queries with bind variables"},
	{id: "CS-VLN-SQLI-SLEEP", category: "sqli", pattern: regexp.MustCompile(`(?i)\bSLEEP\s*\(\s*[0-9]+\s*\)`), severity: SeverityCritical, remediation: "Use parameterized queries; blind timing attacks indicate SQLi"},
	{id: "CS-VLN-SQLI-BENCH", category: "sqli", pattern: regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`), severity: SeverityCritical, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-WAITFOR", category: "sqli", pattern: regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`), severity: SeverityCritical, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-IF-SLEEP", category: "sqli", pattern: regexp.MustCompile(`(?i)\bIF\s*\([^)]*,\s*SLEEP`), severity: SeverityCritical, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-DROP", category: "sqli", pattern: regexp.MustCompile(`(?i);\s*DROP\s+(?:TABLE|DATABASE)\b`), severity: SeverityCritical, remediation: "Use parameterized queries; restrict DB user permissions"},
	{id: "CS-VLN-SQLI-DELETE", category: "sqli", pattern: regexp.MustCompile(`(?i);\s*DELETE\s+FROM\b`), severity: SeverityCritical, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-INSERT", category: "sqli", pattern: regexp.MustCompile(`(?i);\s*INSERT\s+INTO\b`), severity: SeverityHigh, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-UPDATE", category: "sqli", pattern: regexp.MustCompile(`(?i);\s*UPDATE\s+\w+\s+SET\b`), severity: SeverityHigh, remediation: "Use parameterized queries"},
	{id: "CS-VLN-SQLI-ALTER", category: "sqli", pattern: regexp.MustCompile(`(?i);\s*ALTER\s+TABLE\b`), severity: SeverityCritical, remediation: "Use parameterized queries; restrict DB user permissions"},
	{id: "CS-VLN-SQLI-COMMENT", category: "sqli", pattern: regexp.MustCompile(`(?i)(?:--|#|/\*)\s*$`), severity: SeverityMedium, remediation: "Validate and escape SQL comment characters in user input"},

	// SSRF
	{id: "CS-VLN-SSRF-AWS-META", category: "ssrf", pattern: regexp.MustCompile(`169\.254\.169\.254`), severity: SeverityCritical, remediation: "Block requests to cloud metadata endpoints at the network layer"},
	{id: "CS-VLN-SSRF-GCP-META", category: "ssrf", pattern: regexp.MustCompile(`metadata\.google\.internal`), severity: SeverityCritical, remediation: "Block requests to GCP metadata endpoint"},
	{id: "CS-VLN-SSRF-AZ-META", category: "ssrf", pattern: regexp.MustCompile(`169\.254\.169\.254.*metadata`), severity: SeverityCritical, remediation: "Block requests to Azure IMDS endpoint"},
	{id: "CS-VLN-SSRF-ALI-META", category: "ssrf", pattern: regexp.MustCompile(`100\.100\.100\.200`), severity: SeverityCritical, remediation: "Block requests to Alibaba Cloud metadata endpoint"},
	{id: "CS-VLN-SSRF-PRIV-10", category: "ssrf", pattern: regexp.MustCompile(`\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`), severity: SeverityHigh, remediation: "Validate URLs against an allowlist; block private RFC1918 ranges"},
	{id: "CS-VLN-SSRF-PRIV-172", category: "ssrf", pattern: regexp.MustCompile(`\b172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b`), severity: SeverityHigh, remediation: "Validate URLs against an allowlist; block private RFC1918 ranges"},
	{id: "CS-VLN-SSRF-PRIV-192", category: "ssrf", pattern: regexp.MustCompile(`\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b`), severity: SeverityHigh, remediation: "Validate URLs against an allowlist; block private RFC1918 ranges"},
	{id: "CS-VLN-SSRF-LOCALHOST", category: "ssrf", pattern: regexp.MustCompile(`\b127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`), severity: SeverityHigh, remediation: "Block loopback addresses in outbound requests"},
	{id: "CS-VLN-SSRF-OCTAL", category: "ssrf", pattern: regexp.MustCompile(`\b0[0-7]{3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\b`), severity: SeverityHigh, remediation: "Normalize IP representations before validation"},
	{id: "CS-VLN-SSRF-HEX", category: "ssrf", pattern: regexp.MustCompile(`\b0x[0-9a-fA-F]{8}\b`), severity: SeverityMedium, remediation: "Normalize IP representations before validation"},
	{id: "CS-VLN-SSRF-DECIMAL", category: "ssrf", pattern: regexp.MustCompile(`(?i)(?:https?://)\d{8,10}\b`), severity: SeverityHigh, remediation: "Normalize IP representations before validation"},
	{id: "CS-VLN-SSRF-FILE", category: "ssrf", pattern: regexp.MustCompile(`(?i)\bfile://`), severity: SeverityHigh, remediation: "Disallow file:// scheme in user-supplied URLs"},
	{id: "CS-VLN-SSRF-GOPHER", category: "ssrf", pattern: regexp.MustCompile(`(?i)\bgopher://`), severity: SeverityCritical, remediation: "Disallow gopher:// scheme — commonly used for SSRF pivoting"},
	{id: "CS-VLN-SSRF-DICT", category: "ssrf", pattern: regexp.MustCompile(`(?i)\bdict://`), severity: SeverityHigh, remediation: "Disallow dict:// scheme in user-supplied URLs"},

	// Path Traversal
	{id: "CS-VLN-PATH-BASIC", category: "path_traversal", pattern: regexp.MustCompile(`(?:\.\./){2,}`), severity: SeverityHigh, remediation: "Canonicalize paths with filepath.Abs and validate against an allowed root"},
	{id: "CS-VLN-PATH-BACKSLASH", category: "path_traversal", pattern: regexp.MustCompile(`(?:\.\.\\){2,}`), severity: SeverityHigh, remediation: "Canonicalize paths and validate against an allowed root"},
	{id: "CS-VLN-PATH-DOUBLE-ENC", category: "path_traversal", pattern: regexp.MustCompile(`%252[eE]%252[eE]%252[fF]`), severity: SeverityCritical, remediation: "Double-decode URL parameters before path validation"},
	{id: "CS-VLN-PATH-NULL", category: "path_traversal", pattern: regexp.MustCompile(`%00`), severity: SeverityHigh, remediation: "Reject null bytes in file paths"},
	{id: "CS-VLN-PATH-UNC", category: "path_traversal", pattern: regexp.MustCompile(`\\\\[a-zA-Z0-9._\-]+\\`), severity: SeverityHigh, remediation: "Disallow UNC paths in user-supplied filenames"},
	{id: "CS-VLN-PATH-ETC-PASSWD", category: "path_traversal", pattern: regexp.MustCompile(`/etc/(?:passwd|shadow|hosts)`), severity: SeverityCritical, remediation: "Never allow user input to control access to system files"},
	{id: "CS-VLN-PATH-PROC", category: "path_traversal", pattern: regexp.MustCompile(`/proc/(?:self|[0-9]+)/`), severity: SeverityHigh, remediation: "Restrict access to /proc in container and application policy"},
	{id: "CS-VLN-PATH-WIN-SYS", category: "path_traversal", pattern: regexp.MustCompile(`(?i)(?:c:|\\windows)\\system32`), severity: SeverityHigh, remediation: "Disallow access to Windows system directories"},

	// Command Injection
	{id: "CS-VLN-CMDI-SEMI", category: "command_injection", pattern: regexp.MustCompile(`;\s*(?:cat|ls|whoami|id|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php)\b`), severity: SeverityCritical, remediation: "Use subprocess with argument list (not shell=True); validate all inputs"},
	{id: "CS-VLN-CMDI-PIPE", category: "command_injection", pattern: regexp.MustCompile(`\|\s*(?:cat|ls|whoami|id|uname|curl|wget|nc|ncat|bash|sh)\b`), severity: SeverityCritical, remediation: "Use subprocess with argument list; never pass user input to shell"},
	{id: "CS-VLN-CMDI-AMP", category: "command_injection", pattern: regexp.MustCompile(`&{1,2}\s*(?:cat|ls|whoami|id|uname|curl|wget|nc|bash|sh)\b`), severity: SeverityCritical, remediation: "Use subprocess with argument list; never pass user input to shell"},
	{id: "CS-VLN-CMDI-SUBSHELL", category: "command_injection", pattern: regexp.MustCompile(`\$\([^)]*(?:cat|ls|whoami|id|curl|wget|bash|sh)`), severity: SeverityCritical, remediation: "Avoid subshell execution with user-supplied input"},
	{id: "CS-VLN-CMDI-BACKTICK", category: "command_injection", pattern: regexp.MustCompile("`[^`]*(?:cat|ls|whoami|id|uname|curl|wget|nc|ncat|bash|sh)\\s+[^`]+`"), severity: SeverityCritical, remediation: "Avoid backtick command execution with user-supplied input"},
	{id: "CS-VLN-CMDI-ENVVAR", category: "command_injection", pattern: regexp.MustCompile(`\$\{[A-Z_]+\}`), severity: SeverityMedium, remediation: "Validate environment variable expansion in shell contexts"},

	// XSS
	{id: "CS-VLN-XSS-SCRIPT", category: "xss", pattern: regexp.MustCompile(`(?i)<\s*script[^>]*>`), severity: SeverityHigh, remediation: "HTML-encode output; use Content Security Policy"},
	{id: "CS-VLN-XSS-SCRIPT-CLOSE", category: "xss", pattern: regexp.MustCompile(`(?i)</\s*script\s*>`), severity: SeverityHigh, remediation: "HTML-encode output; use Content Security Policy"},
	{id: "CS-VLN-XSS-EVENT", category: "xss", pattern: regexp.MustCompile(`(?i)\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=`), severity: SeverityHigh, remediation: "Never interpolate user data into HTML event attributes"},
	{id: "CS-VLN-XSS-JSPROTO", category: "xss", pattern: regexp.MustCompile(`(?i)javascript\s*:`), severity: SeverityHigh, remediation: "Disallow javascript: URI scheme in user-supplied content"},
	{id: "CS-VLN-XSS-SVG", category: "xss", pattern: regexp.MustCompile(`(?i)<\s*svg[^>]*\bon\w+\s*=`), severity: SeverityHigh, remediation: "Sanitize SVG content; disallow event handlers"},
	{id: "CS-VLN-XSS-OBJECT", category: "xss", pattern: regexp.MustCompile(`(?i)<\s*(?:object|embed|applet|iframe)[^>]*>`), severity: SeverityMedium, remediation: "Avoid object/embed/iframe tags with user-controlled src"},
	{id: "CS-VLN-XSS-COOKIE", category: "xss", pattern: regexp.MustCompile(`(?i)document\.cookie`), severity: SeverityHigh, remediation: "Mark cookies HttpOnly; avoid accessing document.cookie in user contexts"},
	{id: "CS-VLN-XSS-DOCWRITE", category: "xss", pattern: regexp.MustCompile(`(?i)document\.write\s*\(`), severity: SeverityHigh, remediation: "Avoid document.write; use DOM APIs with proper encoding"},
	{id: "CS-VLN-XSS-INNERHTML", category: "xss", pattern: regexp.MustCompile(`(?i)\.innerHTML\s*=`), severity: SeverityMedium, remediation: "Use textContent or sanitize before setting innerHTML"},
	{id: "CS-VLN-XSS-EVAL", category: "xss", pattern: regexp.MustCompile(`(?i)\beval\s*\(`), severity: SeverityHigh, remediation: "Never use eval() with user-supplied content"},
}

func (s *ClawShieldVulnScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name(), Target: target, Timestamp: start}

	files, err := csCollectTextFiles(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: clawshield-vuln: %w", err)
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, csVulnScanContent(content, f)...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func csVulnScanContent(content []byte, path string) []Finding {
	text := string(content)
	var findings []Finding

	for _, rule := range csVulnRules {
		matches := rule.pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			match := text[loc[0]:loc[1]]
			findings = append(findings, Finding{
				ID:          rule.id,
				Severity:    rule.severity,
				Title:       fmt.Sprintf("Vulnerability: %s", rule.id),
				Description: fmt.Sprintf("Category: %s — matched: %s", rule.category, csTruncateMatch(match)),
				Location:    csLocation(path, content, loc[0]),
				Remediation: rule.remediation,
				Scanner:     "clawshield-vuln",
				Tags:        []string{"vulnerability", rule.category, "clawshield"},
			})
		}
	}

	return findings
}
