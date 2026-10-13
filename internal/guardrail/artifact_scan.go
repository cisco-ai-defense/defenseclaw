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

package guardrail

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Static-artifact scanning with a rule pack. `defenseclaw skill scan` applies
// the effective pack's regex rules to the files of a skill on top of the skill
// scanner (cli/defenseclaw/scanner/rulepack.py); the install watcher scans the
// same skill in the gateway, so it applies the same pack the same way. Without
// this a skill the manual scan rejects for a secret in its files was allowed at
// install (GAP-0065).
//
// The selection follows the Python overlay: rules/*.yaml rules that are on, and
// the injection_regexes family of rules/local-patterns.yaml. Rules for data in
// traffic (the enterprise-data category) and rules for tool calls only do not
// describe files. Python source is matched raw, comments and docstrings
// included, on both sides, so a key in a docstring is a finding at install and
// in `skill scan` alike (GAP-0488; owner default, docstring false positives
// are accepted). Only a path-write rule on Python source skips comments and
// docstrings, because it needs a write call using the matched path, as in the
// CLI overlay.

const (
	artifactMaxFileBytes = 512 * 1024
	artifactMaxFiles     = 2000
	// artifactAnalyzerTag marks a finding as produced by the rule-pack overlay
	// of another scanner's result.
	artifactAnalyzerTag = "analyzer:rule-pack"

	artifactTrafficCategory = "enterprise-data"
	artifactInjectionPrefix = "RP-INJECTION"
)

var artifactSkipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "__pycache__": {}, ".venv": {}, "venv": {}, ".mypy_cache": {},
}

var artifactBinaryExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".ico": {}, ".pdf": {}, ".zip": {},
	".gz": {}, ".tar": {}, ".tgz": {}, ".bz2": {}, ".xz": {}, ".7z": {}, ".so": {}, ".dylib": {},
	".dll": {}, ".bin": {}, ".wasm": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".mp4": {},
	".mov": {}, ".mp3": {}, ".wav": {}, ".jar": {}, ".class": {}, ".pyc": {}, ".o": {}, ".a": {},
}

type artifactRule struct {
	id         string
	title      string
	category   string
	severity   scanner.Severity
	confidence float64
	tags       []string
	re         *regexp.Regexp
	// pathWrite marks a rule about writing, appending to or deleting a path.
	pathWrite bool
}

// artifactRules compiles the rules of the pack that describe files.
func (rp *RulePack) artifactRules() []artifactRule {
	var rules []artifactRule
	for _, file := range rp.RuleFiles {
		if file == nil || file.Category == artifactTrafficCategory {
			continue
		}
		for _, def := range file.Rules {
			if def.ToolCallOnly || (def.Enabled != nil && !*def.Enabled) || def.ID == "" || def.Pattern == "" {
				continue
			}
			re, err := regexp.Compile(def.Pattern)
			if err != nil {
				continue
			}
			rules = append(rules, artifactRule{
				id: def.ID, title: def.Title, category: file.Category,
				severity: artifactSeverity(def.Severity), confidence: def.Confidence,
				tags: def.Tags, re: re, pathWrite: isPathWriteExpression(def.Expression),
			})
		}
	}
	if rp.LocalPatterns != nil {
		for index, pattern := range rp.LocalPatterns.InjectionRegexes {
			re, err := regexp.Compile(pattern)
			if pattern == "" || err != nil {
				continue
			}
			rules = append(rules, artifactRule{
				id: fmt.Sprintf("%s-%d", artifactInjectionPrefix, index), title: "Prompt-injection pattern",
				category: "local-pattern", severity: scanner.SeverityHigh,
				tags: []string{"prompt-injection"}, re: re,
			})
		}
	}
	return rules
}

func artifactSeverity(value string) scanner.Severity {
	switch severity := scanner.Severity(strings.ToUpper(strings.TrimSpace(value))); severity {
	case scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo:
		return severity
	}
	return scanner.SeverityMedium
}

func isPathWriteExpression(expression string) bool {
	if !strings.Contains(expression, "f.paths") || strings.Contains(expression, "f.commands") {
		return false
	}
	for _, access := range []string{"WRITE", "APPEND", "DELETE"} {
		if strings.Contains(expression, "PATH_ACCESS_"+access) {
			return true
		}
	}
	return false
}

// ScanArtifact applies the pack's file rules to the text files under path (a
// directory or one file): one finding per rule and file, at the line of the
// first match, located as "relative/path:line". Binary, oversized and
// non-UTF-8 files, symbolic links and vendored directories are skipped. A
// traversal error or a file count beyond artifactMaxFiles fails the scan.
func (rp *RulePack) ScanArtifact(ctx context.Context, path string) ([]scanner.Finding, error) {
	if rp == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rules := rp.artifactRules()
	if len(rules) == 0 {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var findings []scanner.Finding
	if info.Mode().IsRegular() {
		if text, ok := readArtifactText(path); ok {
			findings = scanArtifactText(rules, text, filepath.Base(path))
		}
		return findings, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("artifact %s is not a regular file or directory", path)
	}
	read := 0
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case walkErr != nil:
			return walkErr
		case entry.IsDir():
			if _, skip := artifactSkipDirs[entry.Name()]; skip && current != path {
				return fs.SkipDir
			}
			return nil
		case !entry.Type().IsRegular():
			return nil
		}
		text, ok := readArtifactText(current)
		if !ok {
			return nil
		}
		if read >= artifactMaxFiles {
			return fmt.Errorf("artifact scan exceeds %d readable files", artifactMaxFiles)
		}
		read++
		rel, relErr := filepath.Rel(path, current)
		if relErr != nil {
			rel = entry.Name()
		}
		findings = append(findings, scanArtifactText(rules, text, rel)...)
		return nil
	})
	return findings, err
}

// artifactCommandCategory is the category of the command-line rules
// (rules/commands.yaml).
const artifactCommandCategory = "command"

// artifactDocExts are documentation files.
var artifactDocExts = map[string]struct{}{".md": {}, ".mdx": {}, ".markdown": {}, ".txt": {}, ".rst": {}}

// isArtifactDoc reports a documentation file other than the skill's own
// SKILL.md, which holds the instructions the agent follows.
func isArtifactDoc(location string) bool {
	if _, ok := artifactDocExts[strings.ToLower(filepath.Ext(location))]; !ok {
		return false
	}
	return !strings.EqualFold(filepath.ToSlash(location), "SKILL.md")
}

// firstLineMatch is the first match of re that lies on one line of text.
func firstLineMatch(re *regexp.Regexp, text string) []int {
	offset := 0
	for offset <= len(text) {
		end := strings.IndexByte(text[offset:], '\n')
		line := text[offset:]
		if end >= 0 {
			line = text[offset : offset+end]
		}
		if match := re.FindStringIndex(line); match != nil {
			return []int{offset + match[0], offset + match[1]}
		}
		if end < 0 {
			break
		}
		offset += end + 1
	}
	return nil
}

func scanArtifactText(rules []artifactRule, text, location string) []scanner.Finding {
	python := strings.EqualFold(filepath.Ext(location), ".py")
	doc := isArtifactDoc(location)
	var findings []scanner.Finding
	for _, rule := range rules {
		// A path-write rule in documentation is only a mention of a path.
		if doc && rule.pathWrite {
			continue
		}
		var match []int
		if rule.category == artifactCommandCategory {
			// A command is one line: a match running across lines joined an
			// rm -rf in a JSON example to a "/" further down (GAP-0364).
			match = firstLineMatch(rule.re, text)
		} else if python && rule.pathWrite {
			match = pythonPathWriteMatch(rule.re, text)
		} else {
			match = rule.re.FindStringIndex(text)
		}
		if match == nil {
			continue
		}
		line := 1 + strings.Count(text[:match[0]], "\n")
		findings = append(findings, scanner.Finding{
			ID:       rule.id,
			Severity: rule.severity,
			Title:    rule.title,
			Description: fmt.Sprintf("Matched guardrail rule-pack rule %s (category=%s, confidence=%g).",
				rule.id, rule.category, rule.confidence),
			Location:   fmt.Sprintf("%s:%d", location, line),
			Tags:       append(append([]string(nil), rule.tags...), artifactAnalyzerTag),
			RuleID:     rule.id,
			Category:   rule.category,
			LineNumber: &line,
			Confidence: rule.confidence,
		})
	}
	return findings
}

// readArtifactText reads path as UTF-8 text, or reports false for a binary,
// oversized, unreadable or non-UTF-8 file.
func readArtifactText(path string) (string, bool) {
	if _, binary := artifactBinaryExts[strings.ToLower(filepath.Ext(path))]; binary {
		return "", false
	}
	if info, err := os.Stat(path); err != nil || info.Size() > artifactMaxFileBytes {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > artifactMaxFileBytes {
		return "", false
	}
	// The skill scanner stages UTF-16 manifests as UTF-8. Apply the same
	// decoded content to the rule-pack overlay (GAP-0642).
	if strings.EqualFold(filepath.Base(path), "SKILL.md") {
		data, _ = scanner.DecodeSkillText(data)
	}
	if !utf8.Valid(data) {
		return "", false
	}
	return string(data), true
}

// artifactOverlay adds a rule pack's findings to the result of another scanner.
type artifactOverlay struct {
	scanner.Scanner
	pack *RulePack
}

// NewArtifactOverlay wraps inner so each scan also carries the findings of
// pack's file rules. Findings the inner scanner already reported at the same ID
// and location are not repeated. A nil pack returns inner.
func NewArtifactOverlay(inner scanner.Scanner, pack *RulePack) scanner.Scanner {
	if pack == nil {
		return inner
	}
	return &artifactOverlay{Scanner: inner, pack: pack}
}

func (o *artifactOverlay) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	result, err := o.Scanner.Scan(ctx, target)
	if err != nil || result == nil {
		return result, err
	}
	started := time.Now()
	seen := make(map[[2]string]struct{}, len(result.Findings))
	for _, finding := range result.Findings {
		seen[[2]string{finding.ID, finding.Location}] = struct{}{}
	}
	overlayFindings, err := o.pack.ScanArtifact(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("artifact rule-pack scan: %w", err)
	}
	for _, finding := range overlayFindings {
		if _, duplicate := seen[[2]string{finding.ID, finding.Location}]; duplicate {
			continue
		}
		finding.Scanner = result.Scanner
		result.Findings = append(result.Findings, finding)
	}
	result.Duration += time.Since(started)
	return result, nil
}
