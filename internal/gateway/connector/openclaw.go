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
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// openClawExtensionFS holds the runtime files of the DefenseClaw OpenClaw
// plugin. The tree is synced from extensions/defenseclaw/ by `make
// sync-openclaw-extension` before every gateway build, so the embedded
// contents always match the TypeScript source. Nothing else under
// extensions/ belongs here — only the files OpenClaw actually loads at
// runtime (package.json, openclaw.plugin.json, dist/*.js, and the
// subset of node_modules the plugin requires).
//
//go:embed all:openclaw_extension
var openClawExtensionFS embed.FS

// openClawPluginRoot names the root directory inside openClawExtensionFS.
const openClawPluginRoot = "openclaw_extension"

// OpenClawHomeOverride lets tests redirect the OpenClaw home directory so
// Setup/Teardown write into a scratch path instead of ~/.openclaw.
var OpenClawHomeOverride string

func openClawHome() string {
	if OpenClawHomeOverride != "" {
		return OpenClawHomeOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".openclaw")
}

// OpenClawConnector handles LLM traffic routing and tool inspection for OpenClaw.
// LLM traffic: fetch interceptor plugin patches globalThis.fetch to route
// through the proxy using X-DC-Target-URL and X-AI-Auth headers.
// Tool inspection: same plugin hooks api.on("before_tool_call") and calls
// /api/v1/inspect/tool.
type OpenClawConnector struct {
	gatewayToken string
	masterKey    string
}

// NewOpenClawConnector creates a new OpenClaw connector.
func NewOpenClawConnector() *OpenClawConnector {
	return &OpenClawConnector{}
}

func (c *OpenClawConnector) Name() string                           { return "openclaw" }
func (c *OpenClawConnector) Description() string                    { return "fetch interceptor plugin" }
func (c *OpenClawConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *OpenClawConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *OpenClawConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Surface 1: Install the embedded plugin into OpenClaw and register it
	// in openclaw.json. Enabling the connector is the *only* step an
	// operator needs — no separate `defenseclaw setup guardrail` phase.
	if err := installOpenClawExtension(openClawHome()); err != nil {
		return fmt.Errorf("openclaw extension install: %w", err)
	}

	// Surface 2: Plugin subprocess enforcement
	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("openclaw subprocess enforcement: %w", err)
	}

	// Surface 3: Hook script for tool inspection
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScript(hookDir, opts.APIAddr); err != nil {
		return fmt.Errorf("openclaw hook script: %w", err)
	}

	return nil
}

func (c *OpenClawConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	var errs []string

	if err := uninstallOpenClawExtension(openClawHome()); err != nil {
		errs = append(errs, fmt.Sprintf("uninstall extension: %v", err))
	}

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		errs = append(errs, fmt.Sprintf("subprocess enforcement: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("openclaw teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// installOpenClawExtension writes the embedded plugin files to
// <ocHome>/extensions/defenseclaw and registers the plugin in
// <ocHome>/openclaw.json. Idempotent: re-running leaves the config in the
// same shape (single allow entry, single load path, enabled=true).
func installOpenClawExtension(ocHome string) error {
	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	parentDir := filepath.Join(ocHome, "extensions")

	if err := safeRemoveAll(extDir, parentDir); err != nil {
		return fmt.Errorf("remove prior extension: %w", err)
	}
	if err := writeEmbeddedTree(openClawExtensionFS, openClawPluginRoot, extDir, 0o644, 0o755); err != nil {
		return fmt.Errorf("write plugin files: %w", err)
	}

	configPath := filepath.Join(ocHome, "openclaw.json")
	if err := patchOpenClawConfig(configPath, extDir); err != nil {
		return fmt.Errorf("patch openclaw.json: %w", err)
	}
	return nil
}

// safeRemoveAll removes target only if it resolves to a path under parent.
// This prevents symlink attacks where target is a symlink to an unrelated
// directory (e.g. /etc).
func safeRemoveAll(target, parent string) error {
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		return nil
	}

	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("resolve symlinks for %s: %w", target, err)
	}

	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("resolve parent %s: %w", parent, err)
	}

	if !strings.HasPrefix(resolved, resolvedParent+string(filepath.Separator)) && resolved != resolvedParent {
		return fmt.Errorf("path %s resolves to %s which is outside %s — refusing to remove", target, resolved, resolvedParent)
	}

	return os.RemoveAll(target)
}

// writeEmbeddedTree walks fsys under srcRoot and mirrors every file into
// dstRoot with the same relative layout, creating directories as needed.
// Each target path is checked for path traversal to prevent zip-slip style
// attacks from crafted embed paths. fileMode and dirMode control the
// permissions of written files and directories respectively.
func writeEmbeddedTree(fsys embed.FS, srcRoot, dstRoot string, fileMode, dirMode os.FileMode) error {
	absDstRoot, err := filepath.Abs(dstRoot)
	if err != nil {
		return fmt.Errorf("resolve dstRoot: %w", err)
	}
	return fs.WalkDir(fsys, srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(absDstRoot, rel)
		if !strings.HasPrefix(target, absDstRoot+string(filepath.Separator)) && target != absDstRoot {
			return fmt.Errorf("path traversal detected: %s escapes %s", rel, absDstRoot)
		}
		if d.IsDir() {
			return os.MkdirAll(target, dirMode)
		}
		data, err := fsys.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
			return err
		}
		return os.WriteFile(target, data, fileMode)
	})
}

// patchOpenClawConfig reads openclaw.json (creates it if missing), ensures
// the DefenseClaw plugin is allowed, enabled, and has its extension path
// in plugins.load.paths. Other sections are left untouched.
func patchOpenClawConfig(configPath, extDir string) error {
	return withFileLock(configPath, func() error {
		cfg := map[string]interface{}{}
		if data, err := os.ReadFile(configPath); err == nil && len(data) > 0 {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("parse %s: %w", configPath, err)
			}
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read %s: %w", configPath, err)
		}

		plugins, _ := cfg["plugins"].(map[string]interface{})
		if plugins == nil {
			plugins = map[string]interface{}{}
		}

		plugins["allow"] = appendUniqueString(plugins["allow"], "defenseclaw")

		entries, _ := plugins["entries"].(map[string]interface{})
		if entries == nil {
			entries = map[string]interface{}{}
		}
		entries["defenseclaw"] = map[string]interface{}{"enabled": true}
		plugins["entries"] = entries

		load, _ := plugins["load"].(map[string]interface{})
		if load == nil {
			load = map[string]interface{}{}
		}
		load["paths"] = appendUniqueString(load["paths"], extDir)
		plugins["load"] = load

		cfg["plugins"] = plugins

		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal %s: %w", configPath, err)
		}
		return atomicWriteFile(configPath, append(out, '\n'), 0o644)
	})
}

// uninstallOpenClawExtension removes the extension directory and deletes
// the DefenseClaw entries from openclaw.json, leaving unrelated plugins
// untouched. Returns an error if cleanup fails so the caller can log or
// retry.
func uninstallOpenClawExtension(ocHome string) error {
	var errs []string

	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	parentDir := filepath.Join(ocHome, "extensions")
	if err := safeRemoveAll(extDir, parentDir); err != nil {
		errs = append(errs, fmt.Sprintf("remove extension dir: %v", err))
	}

	configPath := filepath.Join(ocHome, "openclaw.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			if len(errs) > 0 {
				return fmt.Errorf("%s", strings.Join(errs, "; "))
			}
			return nil
		}
		return fmt.Errorf("read openclaw.json: %w", err)
	}

	cfg := map[string]interface{}{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse openclaw.json: %w", err)
	}

	plugins, _ := cfg["plugins"].(map[string]interface{})
	if plugins != nil {
		plugins["allow"] = removeString(plugins["allow"], "defenseclaw")
		if entries, ok := plugins["entries"].(map[string]interface{}); ok {
			delete(entries, "defenseclaw")
			plugins["entries"] = entries
		}
		if load, ok := plugins["load"].(map[string]interface{}); ok {
			load["paths"] = removeString(load["paths"], extDir)
			plugins["load"] = load
		}
		cfg["plugins"] = plugins
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal openclaw.json: %w", err)
	}
	if err := atomicWriteFile(configPath, append(out, '\n'), 0o644); err != nil {
		errs = append(errs, fmt.Sprintf("write openclaw.json: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// appendUniqueString returns a []interface{} with s appended if it is not
// already present. Accepts any upstream interface{} shape (nil, missing,
// or the usual []interface{} JSON produces).
func appendUniqueString(existing interface{}, s string) []interface{} {
	list, _ := existing.([]interface{})
	for _, v := range list {
		if cur, ok := v.(string); ok && cur == s {
			return list
		}
	}
	return append(list, s)
}

// removeString returns a []interface{} with every occurrence of s removed.
func removeString(existing interface{}, s string) []interface{} {
	list, _ := existing.([]interface{})
	out := make([]interface{}, 0, len(list))
	for _, v := range list {
		if cur, ok := v.(string); ok && cur == s {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (c *OpenClawConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check extension directory
	extDir := filepath.Join(openClawHome(), "extensions", "defenseclaw")
	if _, err := os.Stat(extDir); err == nil {
		residual = append(residual, "extensions/defenseclaw still exists")
	}

	// Check openclaw.json for defenseclaw entries
	configPath := filepath.Join(openClawHome(), "openclaw.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg map[string]interface{}
		if json.Unmarshal(data, &cfg) == nil {
			if plugins, ok := cfg["plugins"].(map[string]interface{}); ok {
				if entries, ok := plugins["entries"].(map[string]interface{}); ok {
					if _, found := entries["defenseclaw"]; found {
						residual = append(residual, "openclaw.json still has defenseclaw plugin entry")
					}
				}
				if allow, ok := plugins["allow"].([]interface{}); ok {
					for _, v := range allow {
						if s, ok := v.(string); ok && s == "defenseclaw" {
							residual = append(residual, "openclaw.json allow list still contains defenseclaw")
						}
					}
				}
			}
		}
	}

	// Check shims directory
	shimDir := filepath.Join(opts.DataDir, "shims")
	if entries, err := os.ReadDir(shimDir); err == nil && len(entries) > 0 {
		residual = append(residual, fmt.Sprintf("shims/ still has %d entries", len(entries)))
	}

	if len(residual) > 0 {
		return fmt.Errorf("openclaw teardown incomplete: %s", strings.Join(residual, "; "))
	}
	return nil
}

func (c *OpenClawConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	// Check X-DC-Auth token (set by the fetch interceptor).
	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && SecureTokenMatch(token, c.gatewayToken) {
			return true
		}
	}

	// Check Authorization with the proxy master key.
	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && SecureTokenMatch(strings.TrimPrefix(auth, "Bearer "), c.masterKey) {
			return true
		}
	}

	// No gateway token configured: trust loopback callers. The masterKey is
	// an alternative credential for programmatic/remote access — its presence
	// alone should not revoke loopback trust. The operator opts into requiring
	// auth on all connections by setting DEFENSECLAW_GATEWAY_TOKEN.
	if c.gatewayToken == "" {
		return isLoopback
	}

	return false
}

// SetCredentials injects the gateway token and master key at sidecar boot.
func (c *OpenClawConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *OpenClawConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "openclaw",
		StripHeaders: []string{
			"X-DC-Target-URL", "X-DC-Auth", "X-AI-Auth",
		},
	}

	// X-DC-Target-URL is set by the plugin's fetch interceptor.
	cs.RawUpstream = r.Header.Get("X-DC-Target-URL")

	// X-AI-Auth carries the real provider API key.
	if aiAuth := r.Header.Get("X-AI-Auth"); strings.HasPrefix(aiAuth, "Bearer ") {
		cs.RawAPIKey = strings.TrimPrefix(aiAuth, "Bearer ")
	} else {
		cs.RawAPIKey = ExtractAPIKey(r)
	}

	cs.RawBody = body
	cs.RawModel = ParseModelFromBody(body)
	cs.Stream = ParseStreamFromBody(body)

	// Non-chat paths (Bedrock SigV4, embeddings, etc.) are passthrough.
	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}

// --- ComponentScanner interface ---

func (c *OpenClawConnector) SupportsComponentScanning() bool { return true }

func (c *OpenClawConnector) ComponentTargets(cwd string) map[string][]string {
	home := os.Getenv("HOME")
	openclawHome := filepath.Join(home, ".openclaw")
	workspace := filepath.Join(openclawHome, "workspace")

	targets := map[string][]string{
		"skill":  {filepath.Join(workspace, "skills"), filepath.Join(openclawHome, "skills")},
		"plugin": {filepath.Join(openclawHome, "extensions")},
		"mcp":    {filepath.Join(openclawHome, "openclaw.json")},
		"config": {filepath.Join(openclawHome, "openclaw.json")},
	}
	return targets
}
