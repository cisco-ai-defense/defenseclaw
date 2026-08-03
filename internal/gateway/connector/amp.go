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

package connector

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// AMPPluginPathOverride is a test seam for the user-wide plugin artifact.
// Production always resolves the documented Amp system-plugin location below.
var AMPPluginPathOverride string

// AMPConnector specializes the shared hook-only implementation only where a
// plugin-backed runtime differs from shell-hook connectors: the runtime
// artifact hashed by doctor/guardian is the installed TypeScript file.
type AMPConnector struct {
	*hookOnlyConnector
}

// NewAMPConnector governs Amp (https://ampcode.com). Amp's plugin API exposes
// a synchronous tool.call request hook whose result can allow, reject, or
// defer to native UI confirmation before a tool executes. The same long-lived
// plugin process emits session/agent/tool lifecycle events for Agent360,
// Galileo, audit, and generated hook telemetry.
//
// The plugin is intentionally installed at user scope. Project plugins are
// discoverable and scanned as components, but setup must not modify a
// repository merely to protect the local Amp installation.
func NewAMPConnector() *AMPConnector {
	return &AMPConnector{hookOnlyConnector: &hookOnlyConnector{
		name:                "amp",
		description:         "Amp system policy plugin with pre-tool and model-bound result gating, native confirmation, Agent360, and hook observability",
		apiPath:             "/api/v1/amp/hook",
		scriptName:          "amp-plugin.ts",
		configPath:          ampPluginPath,
		pluginArtifact:      true,
		pluginArtifactAsset: "amp-plugin.ts",
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       true,
				AskEvents:          []string{"tool.call", "tool.result"},
				BlockEvents:        []string{"tool.call", "tool.result"},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         ampPluginPath(opts),
			}
		},
	}}
}

func (c *AMPConnector) HookRuntimeArtifacts(opts SetupOpts) []string {
	return []string{ampPluginPath(opts)}
}

// Authenticate requires an explicit bearer even on loopback. Amp's managed
// plugin always has a header-injection seam and setup requires a
// connector-scoped token, so the legacy unauthenticated-loopback carve-out
// used by shell-hook connectors is neither necessary nor safe here. The
// gateway master remains valid as an intentionally more-privileged
// administrative credential, matching the API middleware's auth contract.
func (c *AMPConnector) Authenticate(r *http.Request) bool {
	if c == nil || c.hookOnlyConnector == nil || r == nil {
		return false
	}
	provided := ExtractBearerKey(r.Header.Get("Authorization"))
	return (c.gatewayToken != "" && SecureTokenMatch(provided, c.gatewayToken)) ||
		(c.masterKey != "" && SecureTokenMatch(provided, c.masterKey))
}

// ownedHookContractPresent verifies Amp's actual agent-visible policy
// registration. The generic hook verifier looks for a shell command inside an
// agent config document, but Amp's registration is the managed TypeScript
// file itself. Keep this check on the concrete connector so other hook-only
// connectors retain their structured config verification.
func (c *AMPConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	path := ampPluginPath(opts)
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := validatePluginArtifactDestination(path); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	for _, marker := range [][]byte{
		[]byte("// defenseclaw-managed-plugin v2"),
		[]byte("/api/v1/amp/hook"),
		[]byte(`amp.on("session.start"`),
		[]byte(`amp.on("agent.start"`),
		[]byte(`amp.on("tool.call"`),
		[]byte(`amp.on("tool.result"`),
		[]byte(`amp.on("agent.end"`),
	} {
		if !bytes.Contains(data, marker) {
			return false, nil
		}
	}
	return true, nil
}

// ampPluginPath resolves the same path on every Amp-supported platform.
// ConfigHome is the lifecycle command's validated native Amp config root
// (~/.config/amp); using it avoids mutating USERPROFILE in a privileged
// process. Interactive callers without that binding use the documented home
// location. On Windows os.UserHomeDir is %USERPROFILE%.
func ampPluginPath(opts SetupOpts) string {
	if AMPPluginPathOverride != "" {
		return AMPPluginPathOverride
	}
	if configHome := strings.TrimSpace(opts.ConfigHome); configHome != "" {
		return filepath.Join(configHome, "plugins", "defenseclaw.ts")
	}
	return homePath(".config", "amp", "plugins", "defenseclaw.ts")
}

func ampSettingsPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".config", "amp", "settings.json"),
		homePath(".config", "amp", "settings.jsonc"),
		workspacePath(opts, ".amp", "settings.json"),
		workspacePath(opts, ".amp", "settings.jsonc"),
		ampManagedSettingsPath(),
	})
}

func ampSkillPaths(opts SetupOpts) []string {
	paths := []string{
		homePath(".config", "agents", "skills"),
		homePath(".agents", "skills"),
		homePath(".config", "amp", "skills"),
		workspacePath(opts, ".agents", "skills"),
	}
	disableClaude := false
	configuredPath := ""
	for _, settingsPath := range ampEffectiveSettingsPaths(opts) {
		document, ok := readAMPSettingsDocument(settingsPath)
		if !ok {
			continue
		}
		if value, exists := document["amp.skills.disableClaudeCodeSkills"].(bool); exists {
			disableClaude = value
		}
		if value, exists := document["amp.skills.path"].(string); exists {
			configuredPath = value
		}
	}
	if !disableClaude {
		paths = append(paths,
			workspacePath(opts, ".claude", "skills"),
			homePath(".claude", "skills"),
		)
		paths = append(paths, ampClaudePluginCacheSkillPaths()...)
	}
	for _, configured := range filepath.SplitList(configuredPath) {
		configured = expandAMPSkillPath(configured, opts)
		if configured != "" {
			paths = append(paths, configured)
		}
	}
	// Plugin-bundled skills have lower precedence than standalone roots.
	for _, pluginRoot := range ampPluginPaths(opts) {
		entries, err := readBoundedAMPDirectory(pluginRoot, 4096)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				paths = append(paths, filepath.Join(pluginRoot, entry.Name(), "skills"))
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func ampEffectiveSettingsPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		preferredAMPSettingsPath(
			homePath(".config", "amp", "settings.json"),
			homePath(".config", "amp", "settings.jsonc"),
		),
		preferredAMPSettingsPath(
			workspacePath(opts, ".amp", "settings.json"),
			workspacePath(opts, ".amp", "settings.jsonc"),
		),
		ampManagedSettingsPath(),
	})
}

func preferredAMPSettingsPath(primary, fallback string) string {
	for _, candidate := range []string{primary, fallback} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return primary
}

func readAMPSettingsDocument(path string) (map[string]interface{}, bool) {
	if path == "" {
		return nil, false
	}
	data, ok := readStableAMPSettingsFile(path)
	if !ok {
		return nil, false
	}
	data = stripAMPJSONCComments(data)
	data = stripAMPJSONCTrailingCommas(data)
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil || document == nil {
		return nil, false
	}
	return document, true
}

const ampSettingsReadLimit int64 = 2 << 20

func readStableAMPSettingsFile(path string) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() || before.Size() > ampSettingsReadLimit {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	opened, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, ampSettingsReadLimit+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil ||
		!opened.Mode().IsRegular() || !os.SameFile(before, opened) ||
		int64(len(data)) > ampSettingsReadLimit {
		return nil, false
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(opened, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, false
	}
	return data, true
}

func stripAMPJSONCComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for index := 0; index < len(data); {
		current := data[index]
		if inString {
			out = append(out, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			index++
			continue
		}
		if current == '"' {
			inString = true
			out = append(out, current)
			index++
			continue
		}
		if current == '/' && index+1 < len(data) && data[index+1] == '/' {
			index += 2
			for index < len(data) && data[index] != '\n' && data[index] != '\r' {
				index++
			}
			continue
		}
		if current == '/' && index+1 < len(data) && data[index+1] == '*' {
			index += 2
			for index+1 < len(data) && !(data[index] == '*' && data[index+1] == '/') {
				index++
			}
			if index+1 < len(data) {
				index += 2
			}
			continue
		}
		out = append(out, current)
		index++
	}
	return out
}

func stripAMPJSONCTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for index := 0; index < len(data); index++ {
		current := data[index]
		if inString {
			out = append(out, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			out = append(out, current)
			continue
		}
		if current == ',' {
			next := index + 1
			for next < len(data) &&
				(data[next] == ' ' || data[next] == '\t' || data[next] == '\n' || data[next] == '\r') {
				next++
			}
			if next < len(data) && (data[next] == '}' || data[next] == ']') {
				continue
			}
		}
		out = append(out, current)
	}
	return out
}

func expandAMPSkillPath(raw string, opts SetupOpts) string {
	path := strings.TrimSpace(os.ExpandEnv(raw))
	if path == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	if path == "~" {
		path = home
	} else if len(path) >= 2 && path[0] == '~' && (path[1] == '/' || path[1] == '\\') {
		remainder := strings.TrimLeft(path[2:], `/\`)
		remainder = filepath.FromSlash(strings.ReplaceAll(remainder, `\`, "/"))
		path = filepath.Join(home, remainder)
	}
	if !filepath.IsAbs(path) {
		root := workspaceRoot(opts)
		if root == "" {
			return ""
		}
		path = filepath.Join(root, path)
	}
	return filepath.Clean(path)
}

// ampClaudePluginCacheSkillPaths expands the Claude-compatible plugin cache
// into actual skills containers. Keep traversal fixed, bounded, and
// symlink-free: the cache hierarchy is not itself a skill root.
func ampClaudePluginCacheSkillPaths() []string {
	const (
		maxDepth   = 4
		maxEntries = 4096
	)
	root := homePath(".claude", "plugins", "cache")
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil
	}
	type pendingDir struct {
		path  string
		depth int
	}
	pending := []pendingDir{{path: root}}
	inspected := 0
	var paths []string
	for len(pending) > 0 && inspected < maxEntries {
		current := pending[0]
		pending = pending[1:]
		entries, err := readBoundedAMPDirectory(current.path, maxEntries-inspected)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			inspected++
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				continue
			}
			depth := current.depth + 1
			child := filepath.Join(current.path, entry.Name())
			if strings.EqualFold(entry.Name(), "skills") {
				paths = append(paths, child)
				continue
			}
			if depth < maxDepth {
				pending = append(pending, pendingDir{path: child, depth: depth})
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func readBoundedAMPDirectory(path string, remaining int) ([]os.DirEntry, error) {
	if remaining <= 0 {
		return nil, nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(remaining)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sort.Slice(entries, func(left, right int) bool {
		return strings.ToLower(entries[left].Name()) < strings.ToLower(entries[right].Name())
	})
	return entries, nil
}

func ampPluginPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".config", "amp", "plugins"),
		workspacePath(opts, ".amp", "plugins"),
	})
}

func ampRulePaths(opts SetupOpts) []string {
	paths := append(ampWorkspaceAgentsPaths(opts),
		workspacePath(opts, ".agents", "checks"),
		homePath(".config", "amp", "AGENTS.md"),
		homePath(".config", "AGENTS.md"),
		homePath(".config", "amp", "checks"),
		homePath(".config", "agents", "checks"),
		ampManagedAgentsPath(),
	)
	return uniqueNonEmptyStrings(paths)
}

func ampSkillWritePaths(opts SetupOpts) []string {
	if root := workspaceRoot(opts); root != "" {
		return []string{filepath.Join(root, ".agents", "skills")}
	}
	return []string{homePath(".config", "agents", "skills")}
}

func ampManagedSettingsPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(string(filepath.Separator), "Library", "Application Support", "ampcode", "managed-settings.json")
	case "linux":
		return filepath.Join(string(filepath.Separator), "etc", "ampcode", "managed-settings.json")
	case "windows":
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "ampcode", "managed-settings.json")
		}
	}
	return ""
}

func ampManagedAgentsPath() string {
	settings := ampManagedSettingsPath()
	if settings == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(settings), "AGENTS.md")
}

// ampWorkspaceAgentsPaths mirrors Amp's guidance lookup for the supplied
// workspace/target directory without following symlinks or traversing broad
// trees. At each directory Amp prefers AGENTS.md, then AGENT.md, then
// CLAUDE.md; ancestor search stops at $HOME. Callers performing a scoped scan
// pass that subtree as WorkspaceDir, matching Amp's on-demand behavior.
func ampWorkspaceAgentsPaths(opts SetupOpts) []string {
	root := filepath.Clean(workspaceRoot(opts))
	if root == "" || root == "." {
		return nil
	}
	home, _ := os.UserHomeDir()
	home = filepath.Clean(home)
	withinHome := false
	if home != "" && home != "." {
		if rel, err := filepath.Rel(home, root); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			withinHome = true
		}
	}
	var paths []string
	for current := root; ; current = filepath.Dir(current) {
		paths = append(paths, ampGuidancePath(current))
		if withinHome && current == home {
			break
		}
		if !withinHome {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}

	return uniqueNonEmptyStrings(paths)
}

func ampGuidancePath(dir string) string {
	if existing := ampExistingGuidancePath(dir); existing != "" {
		return existing
	}
	return filepath.Join(dir, "AGENTS.md")
}

func ampExistingGuidancePath(dir string) string {
	for _, name := range []string{"AGENTS.md", "AGENT.md", "CLAUDE.md"} {
		path := filepath.Join(dir, name)
		if info, err := os.Lstat(path); err == nil &&
			info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}
