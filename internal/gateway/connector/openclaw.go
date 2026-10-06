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
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
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

// openClawPlaceholderName is the marker file the Makefile drops into
// openclaw_extension/ when extensions/defenseclaw/dist is missing at
// build time. Its presence means this gateway binary was built without
// the OpenClaw plugin (e.g. because the operator never ran
// `make extensions`/`make plugin`), and so OpenClaw setup must fail
// with a clear error rather than installing a non-functional shell.
// Other connectors (zeptoclaw, codex, claudecode) don't touch this
// embed at all and remain fully usable.
const openClawPlaceholderName = ".placeholder"

// openClawBundleFiles are the runtime files a usable OpenClaw plugin bundle
// must contain: the manifest OpenClaw reads and the entry point that
// package.json declares. A tree with package.json but no dist/index.js (for
// example a sync from a partial dist/) would install a plugin OpenClaw cannot
// load, so it counts as missing.
var openClawBundleFiles = []string{"package.json", "openclaw.plugin.json", "dist/index.js"}

// openClawExtensionAvailable returns true when the embedded OpenClaw
// extension contains the plugin runtime files and false when it holds only
// the build-time placeholder or a partial sync. This lets the gateway boot
// cleanly for non-OpenClaw operators while still failing loudly when
// someone tries to switch to OpenClaw without having built the plugin.
func openClawExtensionAvailable() bool {
	return openClawBundleComplete(openClawExtensionFS, openClawPluginRoot)
}

func openClawBundleComplete(fsys fs.FS, root string) bool {
	for _, rel := range openClawBundleFiles {
		// fs.FS paths always use forward slashes; filepath.Join would emit
		// backslashes on Windows and never match, so use path.Join.
		if info, err := fs.Stat(fsys, path.Join(root, rel)); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// OpenClawExtensionAvailable reports whether this gateway build embeds the
// optional OpenClaw extension bundle. Non-OpenClaw connectors do not require
// it, and default builds may intentionally contain only the placeholder.
func OpenClawExtensionAvailable() bool {
	return openClawExtensionAvailable()
}

// OpenClawHomeOverride lets tests redirect the OpenClaw home directory so
// Setup/Teardown write into a scratch path instead of ~/.openclaw.
var OpenClawHomeOverride string

func openClawHome() string {
	if OpenClawHomeOverride != "" {
		return OpenClawHomeOverride
	}
	return filepath.Join(userHomeDir(), ".openclaw")
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
	return ResolveSubprocessPolicy(SubprocessShims)
}

// AllowedHosts returns the OpenClaw upstream baseline. The OpenClaw
// fetch interceptor talks to whatever provider the user configured;
// the safe default-deny shipping config covers OpenAI/Anthropic
// (already in firewall.DefaultFirewallConfig) plus the Cisco AI
// Defense inspect endpoint when the OpenClaw plugin is uploading
// findings. This list is *additive* over the static firewall
// defaults — repeating api.openai.com here would be harmless but is
// elided to keep the per-connector contribution honest. See S3.3.
//
// A deployment inspecting through another region or through preview adds its
// own host from config with firewall.MergeAIDefenseEndpoint; the connector
// itself only names the default origin.
func (c *OpenClawConnector) AllowedHosts() []string {
	return []string{
		firewall.AIDefenseAllowlistHost(""),
	}
}

func (c *OpenClawConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Proxy connectors require the local guardrail proxy, which DefenseClaw
	// does not host on Windows (hook-only there). Fail clearly instead of
	// planting a half-configured proxy connector.
	if !ConnectorSupportedOnHostOS(c.Name()) {
		return errConnectorUnsupportedOnOS(c.Name(), runtime.GOOS)
	}

	// The Makefile keeps the gateway buildable on machines without the
	// TS plugin built (typical for non-OpenClaw operators) by embedding
	// a placeholder. If the operator now actually wants OpenClaw, refuse
	// to plant a corrupt extension and tell them how to fix it.
	if !openClawExtensionAvailable() {
		return fmt.Errorf("openclaw extension is not bundled in this gateway build — run 'make extensions' (or 'make plugin') and rebuild the gateway, or pick a different connector with 'defenseclaw setup connector'")
	}

	// Surface 1: Install the embedded plugin into OpenClaw and register it
	// in openclaw.json. Enabling the connector is the *only* step an
	// operator needs — no separate `defenseclaw setup guardrail` phase.
	configPath := filepath.Join(openClawHome(), "openclaw.json")
	keepSnapshot, err := openClawSnapshotUsable(opts.DataDir, c.Name(), configPath)
	if err != nil {
		return fmt.Errorf("openclaw config backup: %w", err)
	}
	if keepSnapshot {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), "openclaw.json", configPath); err != nil {
			return fmt.Errorf("openclaw config backup: %w", err)
		}
	}
	if err := installOpenClawExtension(openClawHome(), opts.HILTEnabled); err != nil {
		return fmt.Errorf("openclaw extension install: %w", err)
	}
	if keepSnapshot {
		if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "openclaw.json", configPath); err != nil {
			return fmt.Errorf("openclaw config backup hash: %w", err)
		}
	}

	// Surface 2: Plugin subprocess enforcement
	policy := ResolveSubprocessPolicy(SubprocessShims)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("openclaw subprocess enforcement: %w", err)
	}

	// Surface 3: Hook script for tool inspection
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("openclaw hook script: %w", err)
	}

	return nil
}

// IsBundledPlugin reports whether dir is DefenseClaw's own OpenClaw plugin
// (~/.openclaw/extensions/defenseclaw) and every file in it is an unmodified
// copy of the bundle this gateway embeds. Files still being written may be
// missing; an added, changed or non-regular file makes it false (GAP-1525).
func (c *OpenClawConnector) IsBundledPlugin(dir string) bool {
	extDir := c.BundledPluginDir()
	got, err1 := filepath.Abs(dir)
	want, err2 := filepath.Abs(extDir)
	if err1 != nil || err2 != nil || filepath.Clean(got) != filepath.Clean(want) {
		return false
	}
	return openClawExtensionMatchesBundle(want)
}

// BundledPluginDir is where Setup installs DefenseClaw's own OpenClaw plugin.
func (c *OpenClawConnector) BundledPluginDir() string {
	return filepath.Join(openClawHome(), "extensions", "defenseclaw")
}

var errNotBundledFile = errors.New("not a bundled file")

func openClawExtensionMatchesBundle(extDir string) bool {
	if !openClawExtensionAvailable() {
		return false
	}
	if info, err := os.Lstat(extDir); err != nil || !info.IsDir() {
		return false
	}
	files := 0
	err := filepath.WalkDir(extDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errNotBundledFile
		}
		rel, err := filepath.Rel(extDir, p)
		if err != nil {
			return err
		}
		want, err := openClawExtensionFS.ReadFile(path.Join(openClawPluginRoot, filepath.ToSlash(rel)))
		if err != nil {
			return errNotBundledFile
		}
		have, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(have, want) {
			return errNotBundledFile
		}
		files++
		return nil
	})
	return err == nil && files > 0
}

// openClawSnapshotUsable reports whether teardown may restore openclaw.json
// from the pre-setup snapshot. Setup runs again on every gateway start, so a
// snapshot is kept only while openclaw.json still holds exactly what DefenseClaw
// last wrote. Once the user (or OpenClaw) changed it, or when there is no
// snapshot but the file already registers DefenseClaw, teardown removes only
// DefenseClaw's own entries and keeps everything else (GAP-1463).
func openClawSnapshotUsable(dataDir, connectorName, configPath string) (bool, error) {
	drifted, err := managedFileBackupDrifted(dataDir, connectorName, "openclaw.json", configPath)
	if err != nil {
		return false, err
	}
	if drifted {
		discardManagedFileBackup(dataDir, connectorName, "openclaw.json")
		return false, nil
	}
	if _, err := os.Stat(managedFileBackupPath(dataDir, connectorName, "openclaw.json")); err == nil {
		return true, nil
	}
	return !openClawConfigRegistersDefenseClaw(configPath), nil
}

// openClawConfigRegistersDefenseClaw reports whether openclaw.json already
// lists the DefenseClaw plugin, so a snapshot of it would not be pre-setup.
func openClawConfigRegistersDefenseClaw(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	cfg := map[string]interface{}{}
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	plugins, _ := cfg["plugins"].(map[string]interface{})
	if plugins == nil {
		return false
	}
	if entries, ok := plugins["entries"].(map[string]interface{}); ok {
		if _, found := entries["defenseclaw"]; found {
			return true
		}
	}
	allow, _ := plugins["allow"].([]interface{})
	for _, v := range allow {
		if s, _ := v.(string); s == "defenseclaw" {
			return true
		}
	}
	return false
}

func (c *OpenClawConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	var errs []string

	configPath := filepath.Join(openClawHome(), "openclaw.json")
	if restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "openclaw.json", configPath); err != nil {
		errs = append(errs, fmt.Sprintf("restore openclaw.json backup: %v", err))
	} else if restored {
		extDir := filepath.Join(openClawHome(), "extensions", "defenseclaw")
		parentDir := filepath.Join(openClawHome(), "extensions")
		if err := safeRemoveAll(extDir, parentDir); err != nil {
			errs = append(errs, fmt.Sprintf("remove extension dir: %v", err))
		}
	} else {
		if err := uninstallOpenClawExtension(openClawHome()); err != nil {
			errs = append(errs, fmt.Sprintf("uninstall extension: %v", err))
		} else {
			discardManagedFileBackup(opts.DataDir, c.Name(), "openclaw.json")
		}
	}

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		errs = append(errs, fmt.Sprintf("subprocess enforcement: %v", err))
	}
	// OpenClaw does not implement HookScriptOwner: it owns only the
	// shared inspect-*.sh family written by every connector's
	// hookwriter, and those are intentionally left in place across
	// connector switches (they're shared infrastructure). Tombstoning
	// is unnecessary because OpenClaw drives tool inspection via the
	// embedded extension, not via a long-lived cached *-hook.sh path
	// in a host agent process.

	if len(errs) > 0 {
		return fmt.Errorf("openclaw teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// installOpenClawExtension writes the embedded plugin files to
// <ocHome>/extensions/defenseclaw and registers the plugin in
// <ocHome>/openclaw.json. Idempotent: re-running leaves the config in the
// same shape (single allow entry, single load path, enabled=true).
func installOpenClawExtension(ocHome string, enablePluginApprovals bool) error {
	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	parentDir := filepath.Join(ocHome, "extensions")

	if err := safeRemoveAll(extDir, parentDir); err != nil {
		return fmt.Errorf("remove prior extension: %w", err)
	}
	if err := writeEmbeddedTree(openClawExtensionFS, openClawPluginRoot, extDir, 0o644, 0o755); err != nil {
		return fmt.Errorf("write plugin files: %w", err)
	}

	configPath := filepath.Join(ocHome, "openclaw.json")
	if err := patchOpenClawConfig(configPath, extDir, enablePluginApprovals); err != nil {
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
		if rel == openClawPlaceholderName {
			// The tracked build marker stays in the embed next to a synced bundle; it is not a plugin file.
			return nil
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
func patchOpenClawConfig(configPath, extDir string, enablePluginApprovals bool) error {
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
		load["paths"] = appendUniqueString(removeDefenseClawLoadPaths(load["paths"]), extDir)
		plugins["load"] = load

		cfg["plugins"] = plugins
		if enablePluginApprovals {
			approvals, _ := cfg["approvals"].(map[string]interface{})
			if approvals == nil {
				approvals = map[string]interface{}{}
			}
			pluginApprovals, _ := approvals["plugin"].(map[string]interface{})
			if pluginApprovals == nil {
				pluginApprovals = map[string]interface{}{}
			}
			pluginApprovals["enabled"] = true
			if _, ok := pluginApprovals["mode"]; !ok {
				pluginApprovals["mode"] = "session"
			}
			approvals["plugin"] = pluginApprovals
			cfg["approvals"] = approvals
		}

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
			load["paths"] = removeDefenseClawLoadPaths(load["paths"])
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

func removeDefenseClawLoadPaths(existing interface{}) []interface{} {
	list, _ := existing.([]interface{})
	out := make([]interface{}, 0, len(list))
	for _, v := range list {
		if isDefenseClawLoadPath(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isDefenseClawLoadPath(value interface{}) bool {
	switch v := value.(type) {
	case string:
		return isDefenseClawPathString(v)
	case map[string]interface{}:
		for _, nested := range v {
			if isDefenseClawLoadPath(nested) {
				return true
			}
		}
	case []interface{}:
		for _, nested := range v {
			if isDefenseClawLoadPath(nested) {
				return true
			}
		}
	}
	return false
}

func isDefenseClawPathString(value string) bool {
	clean := filepath.Clean(strings.TrimSpace(value))
	return filepath.Base(clean) == "defenseclaw"
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

// HasUsableProviders implements ProviderProbe (plan A4). OpenClaw does
// not maintain a provider snapshot: the fetch interceptor plugin
// supplies the upstream URL + key on every call via X-DC-Target-URL /
// X-AI-Auth. As long as openclaw.json has been patched (the plugin is
// installed) and either a gateway token or master key is configured,
// the gateway has at least one usable upstream. We treat the absence
// of credentials as "no upstream" so the boot probe fails fast on
// half-installed deployments.
func (c *OpenClawConnector) HasUsableProviders() (int, error) {
	if c.gatewayToken == "" && c.masterKey == "" {
		return 0, errors.New("openclaw: no gateway token or master key configured; fetch interceptor cannot authenticate to proxy")
	}
	return 1, nil
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

// --- AgentPathProvider / EnvRequirementsProvider / HookScriptProvider ---

// AgentPaths reports the on-disk footprint OpenClaw's connector
// touches. The connector patches ~/.openclaw/openclaw.json (allow
// list + plugin entry) and writes the embedded extension into
// ~/.openclaw/extensions/defenseclaw/. A managed pristine backup under
// <DataDir>/connector_backups backs the config restore path. Hook scripts
// under <DataDir>/hooks/ are written for proxy-side tool inspection.
func (c *OpenClawConnector) AgentPaths(opts SetupOpts) AgentPaths {
	ocHome := openClawHome()
	return AgentPaths{
		PatchedFiles:         []string{filepath.Join(ocHome, "openclaw.json")},
		BackupFiles:          []string{managedFileBackupPath(opts.DataDir, c.Name(), "openclaw.json")},
		HookScripts:          hookScriptPathsForConnector(opts, c),
		GeneratedFiles:       subprocessGeneratedFiles(opts),
		GeneratedExecutables: subprocessGeneratedExecutables(opts),
		CreatedDirs: append([]string{
			filepath.Join(ocHome, "extensions", "defenseclaw"),
		}, subprocessCreatedDirs(opts)...),
	}
}

func (c *OpenClawConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

// RequiredEnv reports the env vars OpenClaw needs for proxy
// routing. OpenClaw uses a fetch interceptor plugin loaded from
// extensions/defenseclaw/ — there is no env var the operator must
// set; the plugin patches globalThis.fetch at runtime. Return a
// single EnvScopeNone entry as positive documentation.
func (c *OpenClawConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{
		{
			Name:        "",
			Scope:       EnvScopeNone,
			Required:    false,
			Description: "OpenClaw routes through DefenseClaw via the embedded fetch interceptor plugin loaded from ~/.openclaw/extensions/defenseclaw/; no env vars are needed.",
		},
	}
}

// --- ComponentScanner interface ---

func (c *OpenClawConnector) SupportsComponentScanning() bool { return true }

func (c *OpenClawConnector) ComponentTargets(cwd string) map[string][]string {
	home := userHomeDir()
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
