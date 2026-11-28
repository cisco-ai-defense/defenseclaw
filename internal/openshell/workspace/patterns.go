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

package workspace

import (
	"io/fs"
	"path"
	"strings"
	"unicode"
)

// matchGlob matches a slash-separated relative path against a pattern.
// Patterns without a slash match the base name at any depth (".env",
// "*.pem"); patterns with a slash match the whole path, where "*", "?" and
// "[...]" work within one segment and "**" spans any number of segments
// ("config/**/prod.yaml", ".github/workflows/*"). A leading "/" anchors
// nothing extra and is ignored. Matching is case-insensitive so a mask
// written as ".ENV" still hides ".env" on case-insensitive filesystems.
func matchGlob(pattern, rel string) bool {
	pattern = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(pattern), "/"))
	rel = strings.ToLower(strings.Trim(rel, "/"))
	if pattern == "" || rel == "" {
		return false
	}
	pattern = strings.TrimSuffix(pattern, "/")
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(rel))
		return ok
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegments(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegments(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], segs[0]); !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// globsReachBelow reports whether a pattern with a slash could match a path
// below the directory dir: its leading segments match dir's, or reach a
// "**" first. Patterns without a slash (base names) and ones that start
// with "**" match at any depth and do not lead a walk into directories it
// skips.
func globsReachBelow(patterns []string, dir string) bool {
	dirSegs := strings.Split(strings.ToLower(strings.Trim(dir, "/")), "/")
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(p), "/")), "/")
		if !strings.Contains(p, "/") || strings.HasPrefix(p, "**") {
			continue
		}
		if segmentsReachBelow(strings.Split(p, "/"), dirSegs) {
			return true
		}
	}
	return false
}

func segmentsReachBelow(pat, dirSegs []string) bool {
	for i, seg := range dirSegs {
		if i >= len(pat) {
			return false
		}
		if pat[i] == "**" {
			return true
		}
		if ok, _ := path.Match(pat[i], seg); !ok {
			return false
		}
	}
	return len(pat) > len(dirSegs)
}

// matchAny returns the first pattern that matches rel.
func matchAny(patterns []string, rel string) (string, bool) {
	for _, p := range patterns {
		if matchGlob(p, rel) {
			return p, true
		}
	}
	return "", false
}

// Built-in secret file names. These mirror the credential names the hook
// layer refuses to trust as source files (codex_hook.go) and the files the
// action-fact classifiers treat as credential stores.
var secretFilePatterns = []string{
	".env", ".env.*", "*.env",
	".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass",
	".my.cnf", ".htpasswd", ".vault-token", ".dockercfg",
	"credentials", "credentials.json", "credentials.yml", "credentials.yaml",
	"auth.json", "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml",
	".secrets", "service-account*.json", "serviceaccount*.json",
	"*-service-account.json", "*serviceAccountKey*.json", "kubeconfig",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
	"*.pem", "*.key", "*.p12", "*.pfx", "*.p8", "*.jks", "*.keystore", "*.kdbx",
	"*.ppk", "*.ovpn", "*.tfstate", "*.tfstate.backup",
}

// Names in secretFilePatterns that are conventionally templates.
var secretFileExceptions = []string{
	".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
	".env.schema", ".env.test.example", "*.env.example", "*.pub",
}

// Directories that are credential stores wherever they appear.
var secretDirNames = []string{
	".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".password-store",
}

// isSecretName reports whether rel names a credential file by convention.
func isSecretName(rel string) (string, bool) {
	if _, ok := matchAny(secretFileExceptions, rel); ok {
		return "", false
	}
	return matchAny(secretFilePatterns, rel)
}

func isSecretDirName(name string) bool {
	name = strings.ToLower(name)
	for _, d := range secretDirNames {
		if name == d {
			return true
		}
	}
	return false
}

// Directories skipped by tree walks: package caches, virtualenvs and tool
// state that are huge and rebuilt from lockfiles or sources. The secret
// scan still checks the entries directly inside them by name, where tools
// keep credentials (see detectSecrets).
var heavyDirNames = map[string]struct{}{
	"node_modules": {}, ".venv": {}, "venv": {}, "__pycache__": {}, ".tox": {},
	".nox": {}, ".mypy_cache": {}, ".pytest_cache": {}, ".ruff_cache": {},
	".gradle": {}, ".terraform": {}, "bower_components": {}, ".next": {},
	".nuxt": {}, ".cache": {}, ".yarn": {}, ".pnpm-store": {},
}

func isHeavyDir(name string) bool {
	_, ok := heavyDirNames[name]
	return ok
}

// Dependency directories whose contents run on the host (npm scripts,
// console entry points) and that an agent can change without touching a
// tracked file. Review fingerprints them.
var dependencyDirNames = []string{"node_modules", ".venv", "venv"}

// RiskKind classifies why a change can run code on the host.
type RiskKind string

const (
	RiskGitControl     RiskKind = "git-control"
	RiskNestedRepo     RiskKind = "nested-repo"
	RiskSubmodule      RiskKind = "submodule"
	RiskGitAttributes  RiskKind = "git-attributes"
	RiskPackageScripts RiskKind = "package-scripts"
	RiskAutoExec       RiskKind = "auto-exec"
	RiskBuild          RiskKind = "build"
	RiskCI             RiskKind = "ci"
	RiskExecutable     RiskKind = "executable"
	RiskSymlink        RiskKind = "symlink"
	RiskSecretFile     RiskKind = "secret-file"
	RiskDependencies   RiskKind = "dependencies"
	RiskPolicy         RiskKind = "sensitive-pattern"
	RiskIgnoreRules    RiskKind = "ignore-rules"
	RiskAgentConfig    RiskKind = "agent-config"
	RiskMCPServer      RiskKind = "mcp-server"
	RiskShellRC        RiskKind = "shell-rc"
	// RiskSecretContext: the agent changed a file that holds a replaced
	// credential (pull of a copy with replaced credentials); the label
	// names the line when the change is next to it.
	RiskSecretContext RiskKind = "secret-context"
	// RiskUnreadable is a folder the session made unreadable: nothing
	// inside it can be checked.
	RiskUnreadable RiskKind = "unreadable"
)

// Severity orders review flags.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityInfo     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	default:
		return 0
	}
}

type riskRule struct {
	patterns []string
	kind     RiskKind
	severity Severity
	detail   string
}

// riskRules are files that run on the host implicitly: when the operator
// opens the folder in an editor, enters it with direnv, installs
// dependencies, commits, builds, or pushes to CI.
var riskRules = []riskRule{
	// An agent that starts in the folder reads these and runs what they
	// register (hooks, commands, MCP servers): one pull could add a hook
	// on this machine (GAP-0473).
	// Agent settings and hook folders. The project hook and MCP configs of
	// every connector also come from the connector registry (registryRules,
	// GAP-0522); these name the hook script folders and settings files the
	// registry does not list. The patterns start with **/ because an agent
	// loads project settings from the folder it is started in, which may be
	// a subfolder.
	{patterns: []string{"**/.claude/settings.json", "**/.claude/settings.local.json", "**/.claude/hooks/**", "**/.codex/config.toml", "**/.codex/hooks.json",
		"**/.cursor/hooks.json", "**/.gemini/settings.json", "**/.gemini/config/hooks.json", "**/.kiro/hooks/**", "**/.github/hooks/**",
		"**/.opencode/**", "**/opencode.json", "**/opencode.jsonc", "**/.amp/settings.json", "**/.amp/settings.jsonc",
		"**/.devin/hooks.v1.json", "**/.devin/config.json", "**/.devin/config.local.json"}, kind: RiskAgentConfig, severity: SeverityHigh, detail: "an agent started in this folder runs the hooks and commands it registers"},
	{patterns: []string{".mcp.json", "**/.cursor/mcp.json", "**/.vscode/mcp.json", "**/.kiro/settings/mcp.json", "**/.gemini/mcp.json",
		"**/.github/mcp.json", "**/.agents/mcp_config.json", "**/.devin/mcp_config.json", "**/.devin/mcp_config.local.json"}, kind: RiskMCPServer, severity: SeverityHigh, detail: "an agent started in this folder launches these MCP servers as commands"},
	{patterns: []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc"}, kind: RiskShellRC, severity: SeverityHigh, detail: "runs in every shell that reads it"},
	{patterns: []string{".envrc", ".env.sh"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "sourced by direnv when you enter the folder"},
	{patterns: []string{".vscode/tasks.json", ".vscode/launch.json", ".vscode/settings.json", "*.code-workspace"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "editor tasks and settings can run commands when the folder is opened"},
	{patterns: []string{".idea/**", ".fleet/**", ".zed/**"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "IDE run configurations execute on the host"},
	{patterns: []string{".devcontainer/**", ".devcontainer.json"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "dev container definitions run commands on the host"},
	{patterns: []string{".pre-commit-config.yaml", ".pre-commit-hooks.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".husky/**", ".githooks/**", ".lintstagedrc*", "lint-staged.config.*", ".overcommit.yml"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "git hook managers run these on your next commit"},
	{patterns: []string{".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", ".pnpmfile.js", "bunfig.toml"}, kind: RiskAutoExec, severity: SeverityHigh, detail: "package-manager config can run code during install"},
	{patterns: []string{".tool-versions", ".mise.toml", "mise.toml", ".mise/**", ".rtx.toml", ".nvmrc", ".node-version", ".python-version"}, kind: RiskAutoExec, severity: SeverityMedium, detail: "version managers act on this when you enter the folder"},
	{patterns: []string{"conftest.py", "pytest.ini", "setup.py", "setup.cfg", "pyproject.toml", "tox.ini", "noxfile.py", "sitecustomize.py", "usercustomize.py", "*.pth"}, kind: RiskBuild, severity: SeverityHigh, detail: "Python tooling executes this on install or test"},
	{patterns: []string{"makefile", "gnumakefile", "*.mk", "justfile", ".justfile", "taskfile.yml", "taskfile.yaml", "rakefile", "*.rake", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew", "gradle/wrapper/**", "mvnw", ".mvn/**", "pom.xml", "cmakelists.txt", "*.cmake", "meson.build", "build.rs", ".cargo/config", ".cargo/config.toml", "build.sbt", "gemfile", "*.gemspec", "composer.json", "deno.json", "deno.jsonc"}, kind: RiskBuild, severity: SeverityHigh, detail: "build tooling runs this on the host"},
	{patterns: []string{".github/workflows/*", ".github/actions/**", ".gitlab-ci.yml", ".gitlab/**", ".circleci/**", "jenkinsfile", "azure-pipelines.yml", ".azure-pipelines/**", ".buildkite/**", ".travis.yml", "bitbucket-pipelines.yml", ".drone.yml", ".woodpecker.yml", ".woodpecker/**"}, kind: RiskCI, severity: SeverityMedium, detail: "CI runs this with your repository's secrets"},
	{patterns: []string{"dockerfile", "*.dockerfile", "containerfile", "docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"}, kind: RiskBuild, severity: SeverityMedium, detail: "container builds run this on the host"},
}

// classifyLinkName is classifyPath for a symbolic link (GAP-0523): a link
// named like a run-code file (.mcp.json, .bashrc, .envrc), or one that
// stands for a folder of a rule at any segment (.claude, .kiro/settings,
// a/.gemini/config), makes that file appear in the folder whatever it
// points to inside the project (GAP-0552). The folder case returns the
// first rule a path below the link would match. Names compare under a
// full Unicode case fold (.kiro/U+017Fettings is .kiro/settings to a
// folding filesystem), not only strings.ToLower (GAP-0575).
func classifyLinkName(rel string) (riskRule, bool) {
	if r, ok := classifyPath(foldName(rel)); ok {
		return r, true
	}
	segs := strings.Split(foldName(strings.Trim(rel, "/")), "/")
	for _, r := range append(append([]riskRule{}, riskRules...), registryRules()...) {
		for _, p := range r.patterns {
			if !strings.Contains(p, "/") {
				continue // a bare file name: classifyPath decided
			}
			if patternReachesBelow(strings.Split(foldName(strings.Trim(p, "/")), "/"), segs) {
				return r, true
			}
		}
	}
	return riskRule{}, false
}

// foldName maps every rune to the lower case of the smallest rune of its
// case-fold orbit, so names that strings.EqualFold equates (s, S and
// U+017F; k and the Kelvin sign) compare equal.
func foldName(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		return unicode.ToLower(m)
	}, s)
}

// sentinelLink reports a symbolic link named like a run-code file or a
// folder a rule reaches below (.kiro/settings, .kiro, out/.kiro/settings):
// git mode's diff cannot see one at a path git ignores, so the sentinel
// walk records it with its target and the review classifies it as it does
// a tracked link (GAP-0574).
func sentinelLink(rel string, d fs.DirEntry) bool {
	if d.Type()&fs.ModeSymlink == 0 {
		return false
	}
	_, ok := classifyLinkName(rel)
	return ok
}

// patternReachesBelow reports whether the link folder segs stands for a
// folder the pattern names, with pattern segments left below it: the link's
// last segment is matched by a named pattern segment (never absorbed by
// "**", or every folder link would count), the segments before it by the
// pattern before that. "**" matches any number of earlier segments.
func patternReachesBelow(pat, segs []string) bool {
	if len(pat) == 0 || len(segs) == 0 {
		return false
	}
	if pat[0] == "**" {
		return patternReachesBelow(pat[1:], segs) || (len(segs) > 1 && patternReachesBelow(pat, segs[1:]))
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false
	}
	if len(segs) == 1 {
		return len(pat) > 1
	}
	return patternReachesBelow(pat[1:], segs[1:])
}

// RunsCode reports whether a change to the project path rel (slash form)
// is flagged as able to run code on this machine (high or medium), the
// rule copy mode and Substrate pull apply. The connector registry drift
// test checks every connector's project MCP and hook config against it
// (GAP-0522).
func RunsCode(rel string) bool {
	r, ok := classifyPath(rel)
	return ok && r.severity.rank() >= SeverityMedium.rank()
}

func classifyPath(rel string) (riskRule, bool) {
	for _, r := range riskRules {
		if _, ok := matchAny(r.patterns, rel); ok {
			return r, true
		}
	}
	for _, r := range registryRules() {
		if _, ok := matchAny(r.patterns, rel); ok {
			return r, true
		}
	}
	return riskRule{}, false
}

// isSentinelPath reports whether a file is tracked by the snapshot's
// sentinel set: every risk-rule file plus package.json and git metadata
// files, which Review re-checks even when git ignores them.
func isSentinelPath(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "package.json", ".gitattributes", ".gitmodules", ".gitignore":
		return true
	}
	_, ok := classifyPath(rel)
	return ok
}
