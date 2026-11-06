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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

type CodeGuardScanner struct {
	RulesDir    string
	customRules []rule
}

// CodeGuardContentScan is the fail-closed result of one in-memory CodeGuard
// evaluation. Its state is private so JSON or another package cannot claim a
// complete scan or manufacture code-owned rule provenance.
type CodeGuardContentScan struct {
	findings []Finding
	complete bool
}

// Findings returns an independent copy of the visible scan findings.
func (r CodeGuardContentScan) Findings() []Finding {
	findings := make([]Finding, len(r.findings))
	for index := range r.findings {
		findings[index] = r.findings[index]
		findings[index].Tags = append([]string(nil), r.findings[index].Tags...)
		findings[index].DataAxis = append([]string(nil), r.findings[index].DataAxis...)
		findings[index].DecisionPath = append(json.RawMessage(nil), r.findings[index].DecisionPath...)
		if r.findings[index].LineNumber != nil {
			line := *r.findings[index].LineNumber
			findings[index].LineNumber = &line
		}
		if r.findings[index].TurnID != nil {
			turn := *r.findings[index].TurnID
			findings[index].TurnID = &turn
		}
	}
	return findings
}

// Complete reports whether the in-process scanner evaluated the whole input.
func (r CodeGuardContentScan) Complete() bool {
	return r.complete
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

func (s *CodeGuardScanner) Name() string               { return "codeguard" }
func (s *CodeGuardScanner) Version() string            { return "1.0.0" }
func (s *CodeGuardScanner) SupportedTargets() []string { return []string{"code"} }

// ScanContent scans an in-memory code string against builtin + custom rules.
// The filename is used for extension-based rule filtering and finding locations.
func codeguardRuleCategory(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) >= 2 {
		return strings.ToLower(parts[1])
	}
	return "codeguard"
}

func (s *CodeGuardScanner) ScanContent(filename, content string) []Finding {
	return s.ScanContentWithProvenance(filename, content).Findings()
}

// ScanContentWithProvenance scans an in-memory code string and retains
// private, code-owned provenance for builtin matches. Custom rules remain
// visible in Findings but never acquire builtin provenance, even if they reuse
// a builtin rule ID.
func (s *CodeGuardScanner) ScanContentWithProvenance(filename, content string) CodeGuardContentScan {
	ext := filepath.Ext(filename)
	var findings []Finding
	rules := s.allRules()

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, r := range rules {
			if len(r.extensions) > 0 && !extMatch(ext, r.extensions) {
				continue
			}
			if r.matches(ext, line) {
				ln := lineNum + 1
				findings = append(findings, Finding{
					ID:                  r.id,
					Severity:            r.severity,
					Title:               r.title,
					Description:         strings.TrimSpace(line),
					Location:            fmt.Sprintf("%s:%d", filename, lineNum+1),
					Remediation:         r.remediation,
					Scanner:             "codeguard",
					Tags:                []string{"codeguard"},
					RuleID:              r.id,
					Category:            codeguardRuleCategory(r.id),
					LineNumber:          &ln,
					codeGuardProvenance: r.provenance,
				})
			}
		}
	}

	return CodeGuardContentScan{findings: findings, complete: true}
}

func (s *CodeGuardScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	if err := requireScannerTargetPath(target); err != nil {
		return nil, err
	}
	start := time.Now()
	var scanErr error
	var result *ScanResult

	result = &ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		TargetType: InferTargetType(s.Name()),
	}

	info, err := os.Stat(target)
	if err != nil {
		scanErr = fmt.Errorf("scanner: codeguard: %w", err)
		return nil, scanErr
	}

	strict := completeScanRequired(ctx)
	var files []string
	if info.IsDir() {
		files, err = collectCodeFiles(target, strict)
		if err != nil {
			scanErr = fmt.Errorf("scanner: codeguard: walk %s: %w", target, err)
			return nil, scanErr
		}
	} else {
		files = []string{target}
	}

	rules := s.allRules()
	for _, f := range files {
		findings, err := scanFileWithRules(f, rules)
		if err != nil {
			// An over-long line is a content limit, not an unread file.
			if strict && !errors.Is(err, bufio.ErrTooLong) {
				return nil, fmt.Errorf("scanner: codeguard: %w", incompleteScan(f, err))
			}
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// codeExtensions are the file extensions CodeGuard scans. Shell and
// Windows script files are code: a PowerShell, batch or zsh script reads
// and writes paths like any other program (GAP-2220: a .ps1 Write with
// "Get-Content ..\temp\secrets.txt" was never scanned on the hook path).
var codeExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true,
	".java": true, ".rb": true, ".php": true, ".sh": true,
	".bash": true, ".zsh": true,
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true,
	".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true,
	".yaml": true, ".yml": true, ".json": true, ".xml": true,
	".c": true, ".cpp": true, ".h": true, ".rs": true,
}

// IsCodeFile reports whether the given file extension is one CodeGuard
// scans. Extensions match without regard to case: Windows paths are case
// insensitive, so "Deploy.PS1" is the same script as "deploy.ps1".
func IsCodeFile(ext string) bool {
	return codeExtensions[strings.ToLower(ext)]
}

// collectCodeFiles skips an unreadable directory or entry unless strict, when
// it fails with ErrIncompleteScan.
func collectCodeFiles(root string, strict bool) ([]string, error) {
	// Avarice F-2952: a malicious skill or plugin tree can place a
	// symlink with a code-extension name pointed at a readable
	// file outside the scan root (e.g. `attacker.py -> /etc/passwd`).
	// The previous walker called codeExtensions[filepath.Ext(path)]
	// without rejecting the symlink, and scanFileWithRules then
	// opened the link target and surfaced its lines as Finding
	// descriptions. We now Lstat each entry, skip symlinks, and
	// also reject any non-regular file just in case.
	absRoot, _ := filepath.Abs(root)
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if strict {
				return incompleteScan(path, err)
			}
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "__pycache__" || base == ".venv" || base == "venv" {
				return filepath.SkipDir
			}
			if perr := probeDirOpen(path); perr != nil {
				if strict {
					return incompleteScan(path, perr)
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !IsCodeFile(filepath.Ext(path)) {
			return nil
		}
		info, lerr := os.Lstat(path)
		if lerr != nil {
			if strict {
				return incompleteScan(path, lerr)
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Defensive: refuse to follow symlinks during scan.
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		// Defense-in-depth: even after rejecting symlinks, ensure
		// the resolved path stays under the scan root.
		if absRoot != "" {
			abs, aerr := filepath.Abs(path)
			if aerr == nil {
				rel, rerr := filepath.Rel(absRoot, abs)
				if rerr != nil || strings.HasPrefix(rel, "..") {
					return nil
				}
			}
		}
		files = append(files, path)
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
	provenance  codeGuardFindingProvenance
	// view, when set, is the part of a line the pattern reads: a built-in
	// rule drops text that only mentions what it looks for (GAP-1226,
	// GAP-1227).
	view func(ext, line string) string
}

// matches reports whether the rule fires on line of a file with extension
// ext.
func (r rule) matches(ext, line string) bool {
	if r.view != nil {
		line = r.view(ext, line)
	}
	return r.pattern.MatchString(line)
}

// pathTraversalModuleSpecifier is the quoted module path of an import,
// require or include statement. The author wrote that path into the
// program; it is not a path built from input, so it is not a traversal.
var pathTraversalModuleSpecifier = lazyregexp.New(`^\s*(?:import|export)\b[^"'` + "`" + `]*\bfrom\s*(?:"[^"$]*"|'[^']*')|^\s*import\s*(?:"[^"$]*"|'[^']*')|\bimport\s*\(\s*(?:"[^"$]*"|'[^']*')|\b(?:require|require_relative|require_once|include|include_once)\s*\(?\s*(?:"[^"$]*"|'[^']*')|^\s*#\s*include\s*(?:"[^"$]*"|'[^']*')|@import\s+(?:url\(\s*)?(?:"[^"$]*"|'[^']*')`)

// pathTraversalProse is a "..." ellipsis that no path separator follows:
// prose ("Loading...", "days...") and an ellipsis before a string escape
// ("Loading...\n", JSON text such as Claude's own onboarding template). An
// ellipsis before "/" or "\" ("....//", "..././", "...\\") and every
// two-dot form ("..\temp", "..\notes") stay path traversal (GAP-1935).
var pathTraversalProse = lazyregexp.New(`\.{3,}(?:\\[nrt"']|[^./\\]|$)`)

// pathTraversalView is the part of a line CG-PATH-001 reads: what the code
// does with a path, not an import of a sibling module or prose (GAP-1226,
// GAP-1227).
func pathTraversalView(_, line string) string {
	line = pathTraversalModuleSpecifier.ReplaceAllString(line, " ")
	return pathTraversalProse.ReplaceAllString(line, " ")
}

// CG-EXEC-001 reads a call of a command or code interpreter, not a name that
// ends in exec, eval or system (GAP-0056): a method of another object
// (re.exec(s), model.eval()), a longer name (parseEval(, createFlysystem()
// and an argument-list subprocess.call([...]) that names no shell run no
// command string. A call right after an escaped line break or tab of a string
// literal (\n, \r, \t) is code in that string and still counts.
//
// The method and name forms that do run a command or code string are named,
// one for each kind of true positive the substring rule found: the os,
// posix and nt modules; child_process and its usual handles (cp,
// childProcess) and module expressions (__import__('os').system(,
// require('child_process').exec(); ShellJS (shell.exec, shelljs.exec); Ruby
// Kernel, Process, binding and TOPLEVEL_BINDING, and instance_/class_/
// module_eval of a string, heredoc or a call left open at the end of the line
// (not a block: class_eval do, (&blk)); Python
// builtins; JavaScript window, globalThis and global eval and jQuery
// globalEval; PHP shell_exec and pcntl_exec. A PHP "->" or "::" call still
// counts, as before. A line with a non-ASCII byte is read in NFKC, as
// Python reads its identifiers.
const (
	// cgExecCommandCalls run a command string. CG-EXEC-002 also reports a
	// subprocess shell=True call; this rule keeps it at its own severity.
	cgExecCommandCalls = `os\.system|\b(?:posix|nt)\.system\(|child_process\.exec|\b(?:cp|childprocess)\.exec\(|` +
		`(?:__import__|import_module|require)\(\s*['"](?:os|(?:node:)?child_process|shelljs)['"]\s*\)\.(?:system|exec)\(|` +
		`\bshell(?:js)?\.exec\(|(?:shell|pcntl)_exec\(|(?:kernel|\bprocess|(?:__)?builtins(?:__)?)\.(?:exec|system)\(|` +
		// subprocess.call runs a command string, or a program chosen at run
		// time, unless its first argument is a list that starts with a
		// literal program name that is no shell, passes no inline code, and
		// the call closes on this line without shell=True (a call left open
		// can take shell=True on the next line).
		`subprocess\.call\((?:\s*[^\s\[]|\s*$|\s*\[\s*[^\s'"\]]|\s*\[[^\]]*$|\s*\[[^\]]*\]\s*(?:,[^)]*)?$|` + cgExecShellListHead + `|` + cgExecInlineCodeList + `|` + cgExecInterpreterFlagList + `|` + cgExecSplitStringList + `)|` +
		`subprocess\.call\(.*shell\s*=\s*true|(?:^|[^.\w$]|\\[nrt])(?:exec|system)\(`
	// cgExecShellListHead is an argument list whose first element is a
	// shell or command interpreter (["sh", "-c", cmd], ["/bin/bash", ...]).
	cgExecShellListHead = `\s*\[\s*['"](?:[^'"]*[/\\])?(?:sh|bash|zsh|dash|ksh|mksh|fish|csh|tcsh|ash|busybox|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|pwsh\.exe)['"]`
	// cgExecInlineCodeList is an argument list that passes inline code or a
	// command string to an interpreter ([sys.executable, "-c", code],
	// ["node", "-e", src], ["node", "--eval", src], ["cmd", "/c", line],
	// ["pwsh", "-Command", s]).
	cgExecInlineCodeList = `\s*\[[^\]]*['"](?:-[a-z]*[ce]|/c|--eval|--eval=[^'"]*|-command|-encodedcommand)['"]`
	// The generic code flags include a short-flag cluster that ends in c or
	// e (python3 -Ic, node -pe, perl -le) and --eval=<code>.
	// cgExecInterpreterFlagList is a JavaScript or PHP interpreter, at any
	// element (behind env, env FOO=1 or sudo; node.exe, php.exe), given a
	// code string through a flag or subcommand that other programs use for
	// something else (node -p/--print, php -r/--run, php -B/-R/-E and
	// --process-begin/-code/-end, deno eval; rm -r, cp -r and pip -r stay
	// exempt).
	cgExecInterpreterFlagList = `\s*\[[^\]]*['"](?:[^'"]*[/\\])?(?:node|nodejs|deno|bun|php)(?:\.exe)?['"][^\]]*['"](?:-[a-z]*[eprb][a-z]*|--print|--run|--process-(?:begin|code|end)|eval)['"]`
	// cgExecSplitStringList is env -S/--split-string given one element that
	// holds a whole command line with an inline-code flag (env -S 'node -p').
	cgExecSplitStringList = `\s*\[[^\]]*['"](?:-s|--split-string)(?:['"]\s*,\s*['"]|=)(?:[^'"]*\s)?(?:-[a-z]*[ce]|--eval\S*|(?:[^'"\s]*[/\\])?(?:node|nodejs|deno|bun|php)(?:\.exe)?\s+(?:[^'"]*\s)?(?:-[a-z]*[eprb][a-z]*|--print|--run|--process-(?:begin|code|end)|eval))['"\s]`
	// cgExecEvalCalls evaluate source text.
	cgExecEvalCalls = `(?:^|[^.\w$]|\\[nrt])eval\(|(?:instance|class|module)_eval\s*(?:\(\s*(?:[^&\s)]|$)|<<|['"%])|globaleval\(|` +
		`(?:__)?(?:builtins(?:__)?|kernel|binding|toplevel_binding|window|globalthis|global)\.eval\(`
)

// cgExecView is the part of a line of a file with extension ext that
// CG-EXEC-001 reads. A line that starts with "//", or in Python, Ruby and
// PHP with "#" (not a PHP "#[" attribute), is a comment up to its first "{":
// from there it can be a template, f-string, JSX or interpolated ("#{...}")
// expression that runs (GAP-0056). In JavaScript "#" starts a private field.
func cgExecView(ext, line string) string {
	// Every pattern names exec, eval, system or subprocess: a line without
	// one is not read, which keeps the rule as fast as the substring rule
	// it replaced.
	if !cgExecHasNeedle(line) {
		return ""
	}
	if !isASCII(line) {
		// Python reads identifiers in NFKC (PEP 3131): a fullwidth,
		// superscript or mathematical "os" names os. Go's (?i) folds only
		// U+017F and U+212A, so the pattern reads the NFKC form.
		line = norm.NFKC.String(line)
	}
	trimmed := strings.TrimLeft(line, " \t")
	comment := strings.HasPrefix(trimmed, "//")
	if !comment && strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#[") {
		switch strings.ToLower(ext) {
		case ".py", ".rb", ".php":
			comment = true
		}
	}
	if !comment {
		return line
	}
	if brace := strings.IndexByte(trimmed, '{'); brace >= 0 {
		return trimmed[brace:]
	}
	return ""
}

// cgExecHasNeedle reports whether line holds exec, eval, system or
// subprocess in any ASCII case, or any non-ASCII byte: the pattern is
// case-insensitive, and Unicode folds letters such as U+017F (long s) to
// ASCII ones that Python reads as the same identifier, so such a line is
// left to the pattern.
func cgExecHasNeedle(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= 0x80 {
			return true
		}
		switch c | 0x20 {
		case 'e':
			if hasFoldASCII(line[i:], "exec") || hasFoldASCII(line[i:], "eval") {
				return true
			}
		case 's':
			if hasFoldASCII(line[i:], "system") || hasFoldASCII(line[i:], "subprocess") {
				return true
			}
		}
	}
	return false
}

// isASCII reports whether line has only ASCII bytes.
func isASCII(line string) bool {
	for i := 0; i < len(line); i++ {
		if line[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasFoldASCII reports whether s starts with the lower-case letters word in
// any ASCII case.
func hasFoldASCII(s, word string) bool {
	if len(s) < len(word) {
		return false
	}
	for j := 0; j < len(word); j++ {
		if s[j]|0x20 != word[j] {
			return false
		}
	}
	return true
}

var builtinRules = codeOwnedBuiltinRules([]rule{
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
		pattern:     regexp.MustCompile(`(?i)` + cgExecCommandCalls + `|` + cgExecEvalCalls),
		remediation: "Use parameterized execution or an allowlist of commands",
		extensions:  []string{".py", ".js", ".ts", ".rb", ".php"},
		view:        cgExecView,
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
		view:        pathTraversalView,
	},
})

func codeOwnedBuiltinRules(rules []rule) []rule {
	for i := range rules {
		rules[i].provenance = codeGuardFindingProvenance{builtinRuleID: rules[i].id}
	}
	return rules
}

func scanFileWithRules(path string, rules []rule) ([]Finding, error) {
	// Avarice F-2952 (defense-in-depth): re-check that path is not
	// a symlink before opening it. The collectCodeFiles walker
	// already rejects symlinks, but this entry point can also be
	// called with a single-file target by Scan().
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("codeguard: refusing to scan symlink %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ext := filepath.Ext(path)
	var findings []Finding

	sc := bufio.NewScanner(f)
	// Avarice F-2953: bufio.Scanner's default token size (64 KiB)
	// makes a single oversized line stop scanning and silently
	// hide every subsequent line from CodeGuard. Generated code
	// can use that to suppress findings — place an oversized
	// line BEFORE the real payload and the rest of the file is
	// scanner-invisible. Raise the buffer to 8 MiB which is well
	// above any realistic source-line length.
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		for _, r := range rules {
			if len(r.extensions) > 0 && !extMatch(ext, r.extensions) {
				continue
			}
			if r.matches(ext, line) {
				ln := lineNum
				findings = append(findings, Finding{
					ID:                  r.id,
					Severity:            r.severity,
					Title:               r.title,
					Description:         strings.TrimSpace(line),
					Location:            fmt.Sprintf("%s:%d", path, lineNum),
					Remediation:         r.remediation,
					Scanner:             "codeguard",
					Tags:                []string{"codeguard"},
					RuleID:              r.id,
					Category:            codeguardRuleCategory(r.id),
					LineNumber:          &ln,
					codeGuardProvenance: r.provenance,
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
