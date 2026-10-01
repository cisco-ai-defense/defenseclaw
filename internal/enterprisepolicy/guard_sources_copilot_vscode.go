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

package enterprisepolicy

import (
	"bufio"
	"bytes"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Copilot hook sources beyond hook files: installed plugins (the CLI and
// VS Code both run their hooks) and, for a request from the VS Code Local
// harness, the sources only that harness reads.
const (
	// formatCopilotPlugins is Copilot's installed-plugins store,
	// <marketplace>/<plugin>/ each with hooks.json or hooks/hooks.json.
	formatCopilotPlugins = "copilot-plugins"
	// formatVSCodeHookLocations is a VS Code settings file whose
	// chat.hookFilesLocations names further hook directories or files.
	formatVSCodeHookLocations = "vscode-hook-locations"
	// formatAgentMarkdownDir is a directory of *.agent.md custom agents
	// whose YAML frontmatter can declare hooks.
	formatAgentMarkdownDir = "agent-markdown-dir"
)

// copilotVSCodeSources adds the Local harness's own sources. They are
// report-only: VS Code, Claude Code or the user owns each file.
func copilotVSCodeSources(req GuardRequest, home string, userWith func(sourceOptions, string, ...string), project func(string, ...string)) {
	if req.HookSurface != connector.CopilotHookSurfaceVSCodeLocal {
		return
	}
	reportOnly := sourceOptions{reportOnly: true}
	// VS Code reads ~/.claude/settings.json; the Copilot CLI does not.
	userWith(reportOnly, formatGrouped, home, ".claude", "settings.json")
	for _, settings := range vscodeUserSettingsPaths(req, home) {
		userWith(reportOnly, formatVSCodeHookLocations, settings)
	}
	project(formatVSCodeHookLocations, ".vscode", "settings.json")
	project(formatAgentMarkdownDir, ".github", "agents")
}

// vscodeUserSettingsPaths are VS Code's (stable and Insiders) user
// settings files under home.
func vscodeUserSettingsPaths(req GuardRequest, home string) []string {
	if home == "" {
		return nil
	}
	var bases []string
	switch req.goos() {
	case "windows":
		if appData := req.getenv("APPDATA"); appData != "" {
			bases = append(bases, appData)
		}
		bases = append(bases, filepath.Join(home, "AppData", "Roaming"))
	case "darwin":
		bases = append(bases, filepath.Join(home, "Library", "Application Support"))
	default:
		if xdg := req.getenv("XDG_CONFIG_HOME"); xdg != "" {
			bases = append(bases, xdg)
		}
		bases = append(bases, filepath.Join(home, ".config"))
	}
	var out []string
	for _, base := range bases {
		for _, product := range []string{"Code", "Code - Insiders"} {
			out = append(out, filepath.Join(base, product, "User", "settings.json"))
		}
	}
	return out
}

// scanCopilotPlugins scans every installed plugin's hook files. A linked
// or unreadable plugin directory cannot be verified and fails closed.
func (s *guardScan) scanCopilotPlugins(store hookSource) []Finding {
	markets, exists, err := s.readDir(store.path)
	if err != nil {
		return []Finding{s.unreadable(store, err)}
	}
	if !exists {
		return nil
	}
	var findings []Finding
	visit := func(entries []fs.DirEntry, dir string, each func(path string)) {
		for _, entry := range entries {
			if s.exceeded != nil {
				return
			}
			name := entry.Name()
			path := filepath.Join(dir, name)
			switch {
			case strings.HasPrefix(name, "."):
			case entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
				findings = append(findings, s.unreadable(store.child(path, formatCopilotPlugins), errLinkedPlugin))
			case entry.IsDir():
				each(path)
			}
		}
	}
	visit(markets, store.path, func(market string) {
		plugins, _, err := s.readDir(market)
		if err != nil {
			findings = append(findings, s.unreadable(store.child(market, formatCopilotPlugins), err))
			return
		}
		visit(plugins, market, func(plugin string) {
			for _, rel := range copilotPluginHookFiles(s, plugin) {
				findings = append(findings, s.scanFile(store.child(filepath.Join(plugin, rel), formatFlat))...)
			}
		})
	})
	return findings
}

var errLinkedPlugin = guardErr("linked plugin directory")

type guardErr string

func (e guardErr) Error() string { return string(e) }

// copilotPluginHookFiles are the hook files a plugin can load: the default
// locations and the manifest's hooks path when it stays inside the plugin.
func copilotPluginHookFiles(s *guardScan, plugin string) []string {
	files := []string{"hooks.json", filepath.Join("hooks", "hooks.json")}
	for _, manifest := range []string{"plugin.json", filepath.Join(".github", "plugin", "plugin.json"), filepath.Join(".claude-plugin", "plugin.json")} {
		data, exists, err := s.readFile(filepath.Join(plugin, manifest))
		if err != nil || !exists {
			continue
		}
		doc, _, err := decodeGuardDocument(data)
		if err != nil {
			continue
		}
		value, _ := doc.get("hooks")
		rel, _ := value.(string)
		rel = filepath.Clean(filepath.FromSlash(strings.TrimSpace(rel)))
		if rel == "." || rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			continue
		}
		duplicate := false
		for _, existing := range files {
			duplicate = duplicate || existing == rel
		}
		if !duplicate {
			files = append(files, rel)
		}
	}
	return files
}

// scanVSCodeHookLocations follows chat.hookFilesLocations: each enabled
// entry is a hook directory or file, relative entries resolving against
// the workspace (the project settings' own root, else the first working
// directory) and ~ against the home.
func (s *guardScan) scanVSCodeHookLocations(source hookSource, data []byte) []Finding {
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	value, ok := doc.get("chat.hookFilesLocations")
	if !ok {
		return nil
	}
	locations, ok := value.(*object)
	if !ok {
		return []Finding{s.unreadable(source, guardErr("chat.hookFilesLocations is not an object"))}
	}
	root := source.base
	if source.scope == ScopeUser {
		root = ""
		if dirs := s.req.workingDirs(); len(dirs) > 0 {
			root = dirs[0]
		}
	}
	var findings []Finding
	for _, location := range locations.keys {
		enabled, _ := locations.get(location)
		if on, _ := enabled.(bool); !on {
			continue
		}
		path := strings.TrimSpace(location)
		switch {
		case path == "~" || strings.HasPrefix(path, "~/"):
			if source.home == "" {
				continue
			}
			path = filepath.Join(source.home, strings.TrimPrefix(path, "~"))
		case !filepath.IsAbs(path):
			if root == "" {
				continue
			}
			path = filepath.Join(root, path)
		}
		child := source.child(filepath.Clean(path), formatFlatDir)
		child.reportOnly = true
		if strings.HasSuffix(strings.ToLower(path), ".json") {
			child.format = formatFlat
			findings = append(findings, s.scanFile(child)...)
		} else {
			findings = append(findings, s.scanFlatDir(child)...)
		}
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

// scanAgentMarkdownDir reports a custom agent whose frontmatter declares
// hooks. DefenseClaw never writes one, so every such agent is foreign and
// approvable only by its digest.
func (s *guardScan) scanAgentMarkdownDir(source hookSource) []Finding {
	entries, exists, err := s.readDir(source.path)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	if !exists {
		return nil
	}
	var findings []Finding
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".agent.md") {
			continue
		}
		child := source.child(filepath.Join(source.path, name), formatAgentMarkdownDir)
		data, _, err := s.readFile(child.path)
		if err != nil {
			findings = append(findings, s.unreadable(child, err))
		} else if agentFrontmatterDeclaresHooks(data) {
			findings = append(findings, findingFor(s.req, child, "", name, sha256Hex(data), "custom agent hooks"))
		}
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

// agentFrontmatterDeclaresHooks reports a top-level hooks key in the
// document's leading YAML frontmatter.
func agentFrontmatterDeclaresHooks(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), guardFileLimit)
	first := true
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if first {
			first = false
			if strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF")) != "---" {
				return false
			}
			continue
		}
		if strings.TrimSpace(line) == "---" {
			return false
		}
		if key, _, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(strings.Trim(key, `"'`)) == "hooks" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			return true
		}
	}
	return false
}
