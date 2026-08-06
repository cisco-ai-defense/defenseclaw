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

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type openCodeConfigLayer struct {
	Source string
	Scope  string
	Data   map[string]any
}

type openCodeUnverifiedConfigSource struct {
	Source string
	Scope  string
	Reason string
}

type openCodeConfigResolution struct {
	Layers     []openCodeConfigLayer
	Unverified []openCodeUnverifiedConfigSource
}

func openCodeEnvPath(value, workspaceDir string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	if root := strings.TrimSpace(workspaceDir); root != "" {
		return filepath.Join(root, value)
	}
	return ""
}

func resolveOpenCodeConfig(workspaceDir string) openCodeConfigResolution {
	resolution := openCodeConfigResolution{Unverified: []openCodeUnverifiedConfigSource{
		{Source: "authenticated .well-known/opencode", Scope: "remote", Reason: "requires OpenCode's authenticated runtime fetch"},
	}}
	type candidate struct{ path, scope string }
	var candidates []candidate
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		root := filepath.Join(home, ".config", "opencode")
		candidates = append(candidates,
			candidate{filepath.Join(root, "config.json"), "global"},
			candidate{filepath.Join(root, "opencode.json"), "global"},
			candidate{filepath.Join(root, "opencode.jsonc"), "global"},
		)
	}
	if raw := os.Getenv("OPENCODE_CONFIG"); raw != "" {
		if path := openCodeEnvPath(raw, workspaceDir); path != "" {
			candidates = append(candidates, candidate{path, "custom-file"})
		} else {
			resolution.Unverified = append(resolution.Unverified, openCodeUnverifiedConfigSource{
				Source: "OPENCODE_CONFIG", Scope: "custom-file", Reason: "relative path has no explicit workspace",
			})
		}
	}
	if root := strings.TrimSpace(workspaceDir); root != "" {
		candidates = append(candidates,
			candidate{filepath.Join(root, "opencode.json"), "project"},
			candidate{filepath.Join(root, "opencode.jsonc"), "project"},
			candidate{filepath.Join(root, ".opencode", "opencode.json"), "project-directory"},
			candidate{filepath.Join(root, ".opencode", "opencode.jsonc"), "project-directory"},
		)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		root := filepath.Join(home, ".opencode")
		candidates = append(candidates,
			candidate{filepath.Join(root, "opencode.json"), "home-directory"},
			candidate{filepath.Join(root, "opencode.jsonc"), "home-directory"},
		)
	}
	if raw := os.Getenv("OPENCODE_CONFIG_DIR"); raw != "" {
		if root := openCodeEnvPath(raw, workspaceDir); root != "" {
			candidates = append(candidates,
				candidate{filepath.Join(root, "opencode.json"), "custom-directory"},
				candidate{filepath.Join(root, "opencode.jsonc"), "custom-directory"},
			)
		} else {
			resolution.Unverified = append(resolution.Unverified, openCodeUnverifiedConfigSource{
				Source: "OPENCODE_CONFIG_DIR", Scope: "custom-directory", Reason: "relative path has no explicit workspace",
			})
		}
	}

	seen := map[string]bool{}
	for _, candidate := range candidates {
		path, err := filepath.Abs(candidate.path)
		if err != nil {
			continue
		}
		key := strings.ToLower(filepath.Clean(path))
		if seen[key] {
			continue
		}
		seen[key] = true
		data, err := os.ReadFile(path)
		if err != nil {
			resolution.Layers = append(resolution.Layers, openCodeConfigLayer{Source: path, Scope: candidate.scope})
			continue
		}
		doc, _ := parseOpenCodeJSONC(data)
		resolution.Layers = append(resolution.Layers, openCodeConfigLayer{Source: path, Scope: candidate.scope, Data: doc})
	}
	if content := os.Getenv("OPENCODE_CONFIG_CONTENT"); content != "" {
		doc, _ := parseOpenCodeJSONC([]byte(content))
		resolution.Layers = append(resolution.Layers, openCodeConfigLayer{
			Source: "OPENCODE_CONFIG_CONTENT", Scope: "inline", Data: doc,
		})
	}
	resolution.Unverified = append(resolution.Unverified, openCodeUnverifiedConfigSource{
		Source: "Windows ProgramData managed config", Scope: "managed-enterprise",
		Reason: "excluded from this non-enterprise connector; effective precedence is unverified",
	})
	return resolution
}

func readMCPServersOpenCode(workspaceDir string) ([]MCPServerEntry, error) {
	resolution := resolveOpenCodeConfig(workspaceDir)
	order := []string{}
	configs := map[string]map[string]any{}
	provenance := map[string]openCodeConfigLayer{}
	for _, layer := range resolution.Layers {
		mcp, ok := layer.Data["mcp"].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(mcp))
		for name := range mcp {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			entry, ok := mcp[name].(map[string]any)
			if !ok {
				continue
			}
			if _, exists := configs[name]; !exists {
				order = append(order, name)
				configs[name] = map[string]any{}
			}
			configs[name] = mergeOpenCodeConfig(configs[name], entry)
			provenance[name] = layer
		}
	}
	entries := make([]MCPServerEntry, 0, len(order))
	for _, name := range order {
		entries = append(entries, openCodeMCPEntry(name, configs[name], provenance[name]))
	}
	return entries, nil
}

func mergeOpenCodeConfig(base, override map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(override))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		if previous, ok := merged[key].(map[string]any); ok {
			if next, ok := value.(map[string]any); ok {
				merged[key] = mergeOpenCodeConfig(previous, next)
				continue
			}
		}
		merged[key] = value
	}
	return merged
}

func openCodeMCPEntry(name string, cfg map[string]any, source openCodeConfigLayer) MCPServerEntry {
	entry := MCPServerEntry{Name: name, Source: source.Source, SourceScope: source.Scope}
	entry.Disabled = cfg["enabled"] == false
	kind, _ := cfg["type"].(string)
	url, _ := cfg["url"].(string)
	command := stringSlice(cfg["command"])
	if strings.EqualFold(strings.TrimSpace(kind), "remote") || (kind == "" && url != "" && len(command) == 0) {
		entry.URL = url
		entry.Transport = "remote"
		entry.Headers = stringMap(cfg["headers"])
		return entry
	}
	entry.Transport = "local"
	if len(command) > 0 {
		entry.Command = command[0]
		entry.Args = command[1:]
	}
	entry.Env = stringMap(cfg["environment"])
	return entry
}

func stringSlice(value any) []string {
	values, ok := value.([]any)
	if !ok {
		if single, ok := value.(string); ok && single != "" {
			return []string{single}
		}
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func stringMap(value any) map[string]string {
	values, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		if text, ok := value.(string); ok {
			out[key] = text
		}
	}
	return out
}

func parseOpenCodeJSONC(data []byte) (map[string]any, error) {
	normalized := stripOpenCodeJSONCComments(data)
	normalized = stripOpenCodeJSONCTrailingCommas(normalized)
	var doc map[string]any
	if err := json.Unmarshal(normalized, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func stripOpenCodeJSONCComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && i+1 < len(data) && data[i+1] == '/' {
			i += 2
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
			if i < len(data) {
				out = append(out, data[i])
			}
			continue
		}
		if ch == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' || data[i] == '\r' {
					out = append(out, data[i])
				}
				i++
			}
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}

func stripOpenCodeJSONCTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, ch)
	}
	return out
}
