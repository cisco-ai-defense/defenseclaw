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
	"path"
	"strings"
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

func classifyPath(rel string) (riskRule, bool) {
	for _, r := range riskRules {
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
