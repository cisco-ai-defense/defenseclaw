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

// Package lockparse extracts (ecosystem, name, version) tuples from
// per-language manifest and lockfile formats so the AI discovery
// service can promote a generic `package_dependency` signal into a
// specific (framework, version) row.
//
// All parsers are bounded, allocation-light, and intentionally lenient:
// a malformed lockfile yields zero entries rather than an error. The
// detector is best-effort fidelity enrichment, not a build-time
// resolver, so we never need exact resolution semantics — we only need
// "for this package name, what version was last installed/declared".
//
// Security:
//   - All parsers use line-bounded scanning and reject inputs above
//     the caller-supplied byte cap to bound CPU/memory.
//   - We never execute the underlying ecosystem's package manager.
//   - JSON parsers reject unknown structures gracefully (no panics on
//     adversarial inputs), and YAML parsers walk the document with a
//     hand-rolled tokenizer instead of pulling in a YAML dependency.
package lockparse

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Component is one parsed dependency entry.
type Component struct {
	Ecosystem string
	Name      string
	Version   string
	Source    string // basename of the manifest/lockfile that produced this entry
}

// MaxFileBytes caps how much of any one file we will read. Anything
// larger is treated as "not parseable" — discovery should not block on
// a single oversized lockfile. The caller can override.
const MaxFileBytes int64 = 4 * 1024 * 1024

// Ecosystem returns the canonical ecosystem string for a manifest or
// lockfile basename, or "" when the basename is not recognised.
//
// Used by callers that want to pick the right per-ecosystem component
// resolver without re-parsing the file.
func Ecosystem(basename string) string {
	switch strings.ToLower(basename) {
	case "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.json", "deno.lock":
		return "npm"
	case "requirements.txt", "requirements-dev.txt", "requirements.in", "constraints.txt",
		"pyproject.toml", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock", "environment.yml", "environment.yaml":
		return "pypi"
	case "cargo.toml", "cargo.lock":
		return "cargo"
	case "go.mod", "go.sum":
		return "go"
	case "gemfile", "gemfile.lock":
		return "rubygems"
	case "composer.json", "composer.lock":
		return "composer"
	case "pom.xml":
		return "maven"
	case "build.gradle", "build.gradle.kts":
		return "gradle"
	case "directory.packages.props", "packages.config":
		return "nuget"
	}
	return ""
}

// Parse dispatches to the right per-ecosystem parser by basename and
// reads from `path` (with size cap). Unknown formats return (nil, nil).
func Parse(path string, maxBytes int64) ([]Component, error) {
	if maxBytes <= 0 {
		maxBytes = MaxFileBytes
	}
	base := filepath.Base(path)
	switch strings.ToLower(base) {
	case "package.json":
		return parseFile(path, maxBytes, parsePackageJSON)
	case "package-lock.json":
		return parseFile(path, maxBytes, parsePackageLockJSON)
	case "pnpm-lock.yaml":
		return parseFile(path, maxBytes, parsePnpmLock)
	case "yarn.lock":
		return parseFile(path, maxBytes, parseYarnLock)
	case "bun.lock":
		return parseFile(path, maxBytes, parseBunLock)
	case "requirements.txt", "requirements-dev.txt", "requirements.in", "constraints.txt":
		return parseFile(path, maxBytes, parseRequirementsTxt)
	case "pyproject.toml":
		return parseFile(path, maxBytes, parsePyprojectToml)
	case "poetry.lock", "uv.lock":
		return parseFile(path, maxBytes, func(r io.Reader) ([]Component, error) {
			return parsePoetryStyleLock(r, "pypi")
		})
	case "pipfile.lock":
		return parseFile(path, maxBytes, parsePipfileLock)
	case "cargo.toml":
		return parseFile(path, maxBytes, parseCargoToml)
	case "cargo.lock":
		return parseFile(path, maxBytes, func(r io.Reader) ([]Component, error) {
			return parsePoetryStyleLock(r, "cargo")
		}) // shares the [[package]] / name / version pattern
	case "go.mod":
		return parseFile(path, maxBytes, parseGoMod)
	case "go.sum":
		return parseFile(path, maxBytes, parseGoSum)
	case "gemfile.lock":
		return parseFile(path, maxBytes, parseGemfileLock)
	case "composer.lock":
		return parseFile(path, maxBytes, parseComposerLock)
	}
	return nil, nil
}

func parseFile(path string, maxBytes int64, fn func(io.Reader) ([]Component, error)) ([]Component, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("lockparse: input is a directory")
	}
	if st.Size() > maxBytes {
		return nil, nil
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	out, err := fn(io.LimitReader(fh, maxBytes))
	if err != nil {
		return nil, err
	}
	source := filepath.Base(path)
	for i := range out {
		out[i].Source = source
		out[i].Name = strings.TrimSpace(out[i].Name)
		out[i].Version = strings.TrimSpace(out[i].Version)
	}
	return out, nil
}

// ---- npm / yarn / pnpm / bun / deno ----

type packageJSONShape struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePackageJSON(r io.Reader) ([]Component, error) {
	var pkg packageJSONShape
	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, nil
	}
	var out []Component
	for _, group := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name, raw := range group {
			out = append(out, Component{
				Ecosystem: "npm",
				Name:      strings.ToLower(name),
				Version:   stripNpmRangePrefix(raw),
			})
		}
	}
	return out, nil
}

// stripNpmRangePrefix turns "^1.45.0" / "~1.0" / ">=1, <2" into the
// best-effort lower bound. We don't resolve ranges (that requires the
// registry); for fidelity reporting we just remove the operator prefix
// so consumers see "1.45.0" instead of "^1.45.0". Workspace / git /
// file: specifiers are returned as-is.
func stripNpmRangePrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "workspace:") || strings.HasPrefix(value, "git+") ||
		strings.HasPrefix(value, "file:") || strings.HasPrefix(value, "npm:") ||
		strings.HasPrefix(value, "link:") || strings.HasPrefix(value, "portal:") {
		return value
	}
	value = strings.TrimLeft(value, "^~>=<")
	value = strings.TrimSpace(value)
	if idx := strings.IndexAny(value, " ,|"); idx >= 0 {
		value = value[:idx]
	}
	return value
}

type packageLockJSONShape struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v2/v3 layout
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	// v1 layout
	Dependencies map[string]struct {
		Version      string                                 `json:"version"`
		Dependencies map[string]packageLockJSONv1Dependency `json:"dependencies"`
	} `json:"dependencies"`
}

type packageLockJSONv1Dependency struct {
	Version      string                                 `json:"version"`
	Dependencies map[string]packageLockJSONv1Dependency `json:"dependencies"`
}

func parsePackageLockJSON(r io.Reader) ([]Component, error) {
	var lock packageLockJSONShape
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil
	}
	out := make([]Component, 0, len(lock.Packages))
	// v2 / v3: keys look like "" (root) and "node_modules/<name>" or
	// "node_modules/<scope>/<name>".
	for key, entry := range lock.Packages {
		if key == "" || entry.Version == "" {
			continue
		}
		idx := strings.Index(key, "node_modules/")
		if idx < 0 {
			continue
		}
		name := key[idx+len("node_modules/"):]
		// Nested pkgs: only take the leaf segment (after the last "node_modules/").
		if last := strings.LastIndex(name, "node_modules/"); last >= 0 {
			name = name[last+len("node_modules/"):]
		}
		out = append(out, Component{
			Ecosystem: "npm",
			Name:      strings.ToLower(name),
			Version:   entry.Version,
		})
	}
	// v1: walk recursively.
	var walk func(deps map[string]packageLockJSONv1Dependency)
	walk = func(deps map[string]packageLockJSONv1Dependency) {
		for name, entry := range deps {
			if entry.Version == "" {
				continue
			}
			out = append(out, Component{
				Ecosystem: "npm",
				Name:      strings.ToLower(name),
				Version:   entry.Version,
			})
			walk(entry.Dependencies)
		}
	}
	for name, entry := range lock.Dependencies {
		if entry.Version != "" {
			out = append(out, Component{
				Ecosystem: "npm",
				Name:      strings.ToLower(name),
				Version:   entry.Version,
			})
		}
		walk(entry.Dependencies)
	}
	return out, nil
}

// parsePnpmLock walks the YAML-ish pnpm lockfile without taking a YAML
// dep. pnpm v6+ emits package keys like:
//
//	packages:
//	  /openai@4.55.0:
//	    resolution: {...}
//
// We scan for `^  /name@version` (or scoped `^  /@scope/name@version`)
// keys under the top-level `packages:` entry.
func parsePnpmLock(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inPackages := false
	var out []Component
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inPackages = strings.HasPrefix(trimmed, "packages:")
			continue
		}
		if !inPackages {
			continue
		}
		// Package keys live exactly two spaces in.
		if !strings.HasPrefix(line, "  /") {
			continue
		}
		key := strings.TrimSuffix(strings.TrimSpace(line), ":")
		key = strings.TrimPrefix(key, "/")
		// Strip suffix like "(...)" used by pnpm peer-dep snapshots.
		if idx := strings.Index(key, "("); idx >= 0 {
			key = key[:idx]
		}
		atIdx := strings.LastIndex(key, "@")
		if atIdx <= 0 {
			continue
		}
		name := key[:atIdx]
		version := key[atIdx+1:]
		if name == "" || version == "" {
			continue
		}
		out = append(out, Component{
			Ecosystem: "npm",
			Name:      strings.ToLower(name),
			Version:   version,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseYarnLock handles classic yarn v1 lockfiles. The Berry (v2+)
// format is YAML and cleanly handled by parsePnpmLock-like scanning.
func parseYarnLock(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	var currentName string
	for scanner.Scan() {
		line := scanner.Text()
		// v1 entry header: `name@spec, name@spec:` or `"name@spec":`
		// Strip surrounding quotes if present.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			head := strings.TrimSuffix(strings.TrimSpace(line), ":")
			head = strings.Trim(head, "\"")
			// First segment is "name@spec".
			if idx := strings.Index(head, ","); idx >= 0 {
				head = head[:idx]
			}
			head = strings.Trim(head, "\"")
			if at := strings.LastIndex(head, "@"); at > 0 {
				currentName = strings.ToLower(head[:at])
			} else {
				currentName = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if currentName == "" || !strings.HasPrefix(trimmed, "version ") && !strings.HasPrefix(trimmed, "version\t") {
			continue
		}
		// `  version "1.0.0"` or `  version 1.0.0`
		v := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
		v = strings.Trim(v, "\"")
		if v == "" {
			continue
		}
		out = append(out, Component{
			Ecosystem: "npm",
			Name:      currentName,
			Version:   v,
		})
		currentName = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseBunLock(r io.Reader) ([]Component, error) {
	// Bun's text lockfile format mirrors npm/yarn semantics for our
	// purpose: lines that look like `"name": "version"` or
	// `"name@version" => …`. Use a JSON pass first; fall back to a
	// regex-light line scan.
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, nil
	}
	var packages struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(body, &packages) == nil && len(packages.Packages) > 0 {
		out := make([]Component, 0, len(packages.Packages))
		for key := range packages.Packages {
			at := strings.LastIndex(key, "@")
			if at <= 0 {
				continue
			}
			out = append(out, Component{
				Ecosystem: "npm",
				Name:      strings.ToLower(key[:at]),
				Version:   key[at+1:],
			})
		}
		return out, nil
	}
	return nil, nil
}

// ---- pypi (requirements / pyproject / poetry / pipfile) ----

func parseRequirementsTxt(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	for scanner.Scan() {
		line := scanner.Text()
		// Strip comments and surrounding whitespace.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "--") {
			continue
		}
		// Drop environment markers (PEP 508): "pkg==1.0; python_version >= '3.10'"
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Split by the first comparison operator.
		name, version := splitRequirementSpec(line)
		if name == "" {
			continue
		}
		out = append(out, Component{
			Ecosystem: "pypi",
			Name:      normalizePypiName(name),
			Version:   version,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func splitRequirementSpec(line string) (string, string) {
	for _, op := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(line, op); idx > 0 {
			return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+len(op):])
		}
	}
	// "pkg @ git+https://…" — keep the name only.
	if idx := strings.IndexByte(line, '@'); idx > 0 {
		return strings.TrimSpace(line[:idx]), ""
	}
	// Bare name ("pkg" or "pkg [extras]").
	name := strings.TrimSpace(line)
	if idx := strings.IndexByte(name, '['); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name, ""
}

func normalizePypiName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// PEP 503: replace runs of [-_.] with single "-".
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch r {
		case '-', '_', '.':
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		default:
			b.WriteRune(r)
			lastDash = false
		}
	}
	return strings.Trim(b.String(), "-")
}

// parsePyprojectToml is a deliberately minimal TOML walk: we look for
// `[project]` -> `dependencies = [...]` (PEP 621) and `[tool.poetry.dependencies]`.
// Anything else (uv tool, hatch, pdm) typically tracks PEP 621 too.
func parsePyprojectToml(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	section := ""
	inDepsArray := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.Trim(trimmed, "[]")
			inDepsArray = false
			continue
		}
		switch section {
		case "project":
			if strings.HasPrefix(trimmed, "dependencies") {
				inDepsArray = strings.Contains(trimmed, "[") && !strings.Contains(trimmed, "]")
				// Single-line array: parse inline.
				if strings.Contains(trimmed, "[") && strings.Contains(trimmed, "]") {
					out = append(out, parseInlineDepArray(trimmed)...)
				}
				continue
			}
			if inDepsArray {
				if strings.Contains(trimmed, "]") {
					inDepsArray = false
				}
				if dep := unquoteDep(strings.TrimRight(trimmed, ",")); dep != "" {
					if name, version := splitRequirementSpec(dep); name != "" {
						out = append(out, Component{Ecosystem: "pypi", Name: normalizePypiName(name), Version: version})
					}
				}
			}
		case "tool.poetry.dependencies", "tool.poetry.group.dev.dependencies", "tool.poetry.group.test.dependencies":
			// `name = "^1.0"` or `name = { version = "1.0" }`
			if eq := strings.IndexByte(trimmed, '='); eq > 0 {
				name := strings.TrimSpace(trimmed[:eq])
				if name == "python" || name == "" {
					continue
				}
				rhs := strings.TrimSpace(trimmed[eq+1:])
				version := ""
				if strings.HasPrefix(rhs, "\"") {
					version = stripNpmRangePrefix(strings.Trim(rhs, "\""))
				} else if strings.HasPrefix(rhs, "{") {
					if v := extractInlineKey(rhs, "version"); v != "" {
						version = stripNpmRangePrefix(v)
					}
				}
				out = append(out, Component{Ecosystem: "pypi", Name: normalizePypiName(name), Version: version})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseInlineDepArray(line string) []Component {
	body := line
	if i := strings.Index(body, "["); i >= 0 {
		body = body[i+1:]
	}
	if j := strings.Index(body, "]"); j >= 0 {
		body = body[:j]
	}
	var out []Component
	for _, part := range strings.Split(body, ",") {
		dep := unquoteDep(strings.TrimSpace(part))
		if dep == "" {
			continue
		}
		if name, version := splitRequirementSpec(dep); name != "" {
			out = append(out, Component{Ecosystem: "pypi", Name: normalizePypiName(name), Version: version})
		}
	}
	return out
}

func unquoteDep(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func extractInlineKey(s, key string) string {
	target := key + " = \""
	idx := strings.Index(s, target)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(target):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// parsePoetryStyleLock handles poetry.lock / uv.lock / Cargo.lock -- all
// share the same `[[package]] / name = "x" / version = "y"` shape.
func parsePoetryStyleLock(r io.Reader, ecosystem string) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	var current Component
	inPackage := false
	flush := func() {
		if inPackage && current.Name != "" {
			out = append(out, current)
		}
		current = Component{}
		inPackage = false
	}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		if !inPackage {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			flush()
			continue
		}
		if eq := strings.IndexByte(trimmed, '='); eq > 0 {
			key := strings.TrimSpace(trimmed[:eq])
			val := strings.Trim(strings.TrimSpace(trimmed[eq+1:]), "\"")
			switch key {
			case "name":
				current.Name = val
			case "version":
				current.Version = val
			}
		}
	}
	flush()
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if ecosystem == "" {
		ecosystem = "pypi"
	}
	for i := range out {
		out[i].Ecosystem = ecosystem
		if ecosystem == "pypi" {
			out[i].Name = normalizePypiName(out[i].Name)
		} else {
			out[i].Name = strings.ToLower(strings.TrimSpace(out[i].Name))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parsePipfileLock(r io.Reader) ([]Component, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, nil
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if json.Unmarshal(body, &lock) != nil {
		return nil, nil
	}
	var out []Component
	for _, group := range []map[string]struct {
		Version string `json:"version"`
	}{lock.Default, lock.Develop} {
		for name, entry := range group {
			version := strings.TrimPrefix(strings.TrimSpace(entry.Version), "==")
			out = append(out, Component{Ecosystem: "pypi", Name: normalizePypiName(name), Version: version})
		}
	}
	return out, nil
}

// ---- cargo ----

func parseCargoToml(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	section := ""
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.Trim(trimmed, "[]")
			continue
		}
		if section != "dependencies" && section != "dev-dependencies" && section != "build-dependencies" {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		name := strings.TrimSpace(trimmed[:eq])
		rhs := strings.TrimSpace(trimmed[eq+1:])
		version := ""
		if strings.HasPrefix(rhs, "\"") {
			version = stripNpmRangePrefix(strings.Trim(rhs, "\""))
		} else if strings.HasPrefix(rhs, "{") {
			if v := extractInlineKey(rhs, "version"); v != "" {
				version = stripNpmRangePrefix(v)
			}
		}
		out = append(out, Component{Ecosystem: "cargo", Name: strings.ToLower(name), Version: version})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- go ----

func parseGoMod(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	inRequireBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && trimmed == ")" {
			inRequireBlock = false
			continue
		}
		if inRequireBlock {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				out = append(out, Component{Ecosystem: "go", Name: strings.ToLower(fields[0]), Version: fields[1]})
			}
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			fields := strings.Fields(strings.TrimPrefix(trimmed, "require "))
			if len(fields) >= 2 {
				out = append(out, Component{Ecosystem: "go", Name: strings.ToLower(fields[0]), Version: fields[1]})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseGoSum(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	seen := map[string]string{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Skip the `/go.mod` lines so each module appears once.
		if strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		seen[strings.ToLower(fields[0])] = fields[1]
	}
	out := make([]Component, 0, len(seen))
	for name, version := range seen {
		out = append(out, Component{Ecosystem: "go", Name: name, Version: version})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- ruby ----

func parseGemfileLock(r io.Reader) ([]Component, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Component
	inSpecs := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// Section ends at the next blank top-level line.
		if !strings.HasPrefix(line, "    ") {
			if trimmed == "" || !strings.HasPrefix(line, "  ") {
				inSpecs = false
				continue
			}
		}
		// `    name (version)`
		fields := strings.Fields(trimmed)
		if len(fields) < 1 {
			continue
		}
		name := strings.ToLower(fields[0])
		version := ""
		if len(fields) >= 2 {
			version = strings.Trim(fields[1], "()")
		}
		out = append(out, Component{Ecosystem: "rubygems", Name: name, Version: version})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- composer ----

func parseComposerLock(r io.Reader) ([]Component, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, nil
	}
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(body, &lock) != nil {
		return nil, nil
	}
	var out []Component
	for _, group := range [][]struct{ Name, Version string }{lock.Packages, lock.PackagesDev} {
		for _, pkg := range group {
			if pkg.Name == "" {
				continue
			}
			out = append(out, Component{Ecosystem: "composer", Name: strings.ToLower(pkg.Name), Version: strings.TrimSpace(pkg.Version)})
		}
	}
	return out, nil
}

// ---- helpers ----

// IndexByName turns a parsed component slice into a name→version map
// for the given ecosystem (case-insensitive name lookup). Useful for
// the AI discovery detector that wants to enrich a manifest match
// with a co-located lockfile's resolved version.
func IndexByName(components []Component, ecosystem string) map[string]string {
	ecosystem = strings.ToLower(ecosystem)
	out := map[string]string{}
	for _, c := range components {
		if ecosystem != "" && strings.ToLower(c.Ecosystem) != ecosystem {
			continue
		}
		name := strings.ToLower(c.Name)
		if name == "" {
			continue
		}
		if existing := out[name]; existing == "" {
			out[name] = c.Version
		}
	}
	return out
}

// FormatError is exposed for tests that want to assert on parser
// rejection wording without coupling to `errors.New(...)` strings.
func FormatError(format string, args ...any) error { return fmt.Errorf(format, args...) }
