// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// HookConfigPathsForConnector returns the absolute agent config file path(s)
// that the given connector patches with DefenseClaw hook entries (e.g.
// ~/.cursor/hooks.json, ~/.claude/settings.json, ~/.codex/config.toml).
//
// It returns nil for proxy/plugin connectors that do not register lifecycle
// hooks in an agent config file (openclaw, zeptoclaw). Shell-hook owners and
// non-shell policy-module owners both expose repairable config references.
//
// The resolved paths come from ResolvedConnectorLocations, the same path
// contract captured into hook_contract_lock.json, so the guard watches
// exactly the files Setup writes.
func HookConfigPathsForConnector(conn Connector, opts SetupOpts) []string {
	if conn == nil {
		return nil
	}
	if !OwnsManagedHookRuntime(conn) {
		return nil
	}
	return uniqueNonEmptyStrings(ResolvedConnectorLocations(opts, conn).HookConfigPaths)
}

// HookPolicyWatchPathsForConnector returns every locally inspectable file that
// can change the effective hook decision. Setup/teardown still own only
// HookConfigPathsForConnector; this wider set exists solely so the runtime
// guardian re-evaluates policy when Claude's higher-precedence sources change.
func HookPolicyWatchPathsForConnector(conn Connector, opts SetupOpts) []string {
	paths := HookConfigPathsForConnector(conn, opts)
	if conn == nil || conn.Name() != "claudecode" {
		return paths
	}
	paths = append(paths, claudeCodeRemoteSettingsPath())
	if workspace := strings.TrimSpace(opts.WorkspaceDir); workspace != "" {
		workspace = filepath.Clean(workspace)
		projectDir := filepath.Join(workspace, ".claude")
		// The directory itself lets a watcher on workspace observe first-time
		// creation; the two files cover subsequent scalar policy edits.
		paths = append(paths,
			projectDir,
			filepath.Join(projectDir, "settings.json"),
			filepath.Join(projectDir, "settings.local.json"),
		)
	}
	if managedRoot, err := claudeCodeManagedSettingsRoot(); err == nil {
		paths = append(paths, filepath.Join(managedRoot, "managed-settings.json"))
		dropin := filepath.Join(managedRoot, "managed-settings.d")
		paths = append(paths, dropin)
		if entries, err := os.ReadDir(dropin); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if !entry.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(strings.ToLower(name), ".json") {
					paths = append(paths, filepath.Join(dropin, name))
				}
			}
		}
	}
	if raw := strings.TrimSpace(opts.ClaudeSettingsOverride); raw != "" && !strings.HasPrefix(raw, "{") {
		if source, err := readClaudeCodeCLISettings(raw, strings.TrimSpace(opts.WorkspaceDir)); err == nil && source != nil {
			paths = append(paths, source.path)
		}
	}
	return uniqueNonEmptyStrings(paths)
}

// ownedHookCommandNeedles returns escaping-invariant marker string(s) that the
// connector writes into its agent config, used for a raw-bytes substring match
// against the live config file. See ownedHookCommandNeedlesFor for the
// platform rationale.
//
// Returns nil for connectors that own no vendor hook script (openclaw,
// zeptoclaw), keeping the self-heal guard inert for them.
func ownedHookCommandNeedles(opts SetupOpts, conn Connector) []string {
	return ownedHookCommandNeedlesFor(runtime.GOOS, opts, conn)
}

// ownedHookCommandNeedlesFor is the OS-parameterized core of
// ownedHookCommandNeedles, split out so the Windows marker can be exercised by
// tests on any host.
//
// The needle must survive serialization into the agent config file, because
// OwnedHooksPresent matches it against the raw file bytes (not a decoded
// value). That constraint differs by platform:
//
//   - Unix: the agent runs the bundled .sh hook, so the config stores the
//     absolute script path under <DataDir>/hooks/. Forward-slash paths contain
//     no characters JSON/TOML/YAML escape, so the path appears verbatim.
//
//   - Windows: most connectors store the native invocation
//     (`"C:\...\defenseclaw-hook.exe" hook --connector <name>`). The absolute
//     exe path's backslashes and surrounding quotes are escaped during config
//     serialization, so their stable marker is `hook --connector <name>`.
//     Cursor and Windsurf are matched exactly because their native transports
//     require generated PowerShell adapters. Antigravity is also matched
//     exactly because its direct-exec tokenizer requires a PowerShell
//     encoded-command wrapper rather than a visibly quoted absolute executable
//     path.
func ownedHookCommandNeedlesFor(goos string, opts SetupOpts, conn Connector) []string {
	if owner, ok := conn.(HookConfigReferenceOwner); ok {
		return uniqueNonEmptyStrings(owner.HookConfigReferenceNeedles(opts))
	}
	owner, ok := conn.(HookScriptOwner)
	if !ok {
		return nil
	}
	scriptNames := owner.HookScriptNames(opts)
	if len(scriptNames) != 0 {
		hookScript := filepath.Join(opts.DataDir, "hooks", scriptNames[0])
		switch conn.Name() {
		case "copilot":
			events := copilotCurrentHookEvents
			if provider, profileOK := conn.(HookProfileProvider); profileOK {
				if resolved := provider.HookProfile(opts).SupportedEvents; len(resolved) != 0 {
					events = resolved
				}
			}
			needles := make([]string, 0, len(events))
			for _, event := range events {
				needles = append(needles, copilotHookInvocationCommandForEvent(goos, event, hookScript))
			}
			return uniqueNonEmptyStrings(needles)
		case "antigravity":
			return antigravityOwnedHookCommandsForOS(goos, hookScript)
		}
	}
	if goos == "windows" {
		if conn.Name() == "cursor" || conn.Name() == "windsurf" {
			unixCommand := filepath.Join(opts.DataDir, "hooks", conn.Name()+"-hook.sh")
			return []string{hookInvocationCommandFor("windows", conn.Name(), unixCommand)}
		}
		return []string{nativeHookFlag + conn.Name()}
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var needles []string
	for _, name := range owner.HookScriptNames(opts) {
		if path := filepath.Join(hookDir, name); path != "" {
			needles = append(needles, path)
		}
	}
	return needles
}

// OwnedHooksPresent reports whether the connector's DefenseClaw hook entries
// are still present in every agent config file it patches. It returns false
// (heal needed) when any watched config file is missing entirely or no longer
// references our hook command.
//
// Connectors with no hook config paths or no owned hook command (proxy/plugin
// connectors) are reported as present so the guard never tries to heal them.
type ownedHookContractInspector interface {
	ownedHookContractPresent(SetupOpts) (bool, error)
}

func OwnedHooksPresent(conn Connector, opts SetupOpts) (bool, error) {
	if cursor, ok := conn.(*hookOnlyConnector); ok && cursor.name == "cursor" {
		return cursor.ownedCursorHookContractPresent(opts)
	}
	if conn != nil && conn.Name() == "windsurf" {
		windsurf, ok := conn.(*hookOnlyConnector)
		if !ok {
			return false, errors.New("windsurf hook contract requires the native Cascade connector")
		}
		return windsurfOwnedHooksPresentForOS(windsurf, opts, runtime.GOOS)
	}
	if inspector, ok := conn.(ownedHookContractInspector); ok {
		return inspector.ownedHookContractPresent(opts)
	}
	if conn != nil && conn.Name() == "opencode" {
		return openCodeManagedPluginPresent(conn, opts)
	}
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) == 0 {
		return true, nil
	}
	needles := ownedHookCommandNeedles(opts, conn)
	if len(needles) == 0 {
		return true, nil
	}
	for _, path := range paths {
		present, err := configFileReferencesHook(path, needles)
		if err != nil {
			return false, err
		}
		if !present {
			return false, nil
		}
	}
	return true, nil
}

// windsurfOwnedHooksPresentForOS validates the effective legacy Cascade
// contract, not merely the presence of one DefenseClaw path. Readiness requires
// exactly one managed handler on every documented event. Foreign handlers and
// future event keys remain untouched and do not make the managed contract
// unhealthy.
func windsurfOwnedHooksPresentForOS(conn *hookOnlyConnector, opts SetupOpts, goos string) (bool, error) {
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) != 1 {
		return false, fmt.Errorf("windsurf Cascade hook config path count is %d; want 1", len(paths))
	}
	cfg, err := readJSONObject(paths[0])
	if err != nil {
		return false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	expected := conn.hookCommandForOS(goos, opts)
	for _, event := range windsurfCascadeHookEvents {
		entries, ok := hooks[event].([]interface{})
		if !ok {
			return false, nil
		}
		managed := 0
		for _, raw := range entries {
			owned := managedHookCommandEntry(raw, expected) ||
				managedHookCommandEntry(raw, filepath.Join(opts.DataDir, "hooks", conn.scriptName)) ||
				managedHookCommandEntry(raw, legacyWindsurfWindowsHookCommand())
			if !owned {
				continue
			}
			if !windsurfManagedHookEntryMatches(raw, expected, goos) {
				return false, nil
			}
			managed++
		}
		if managed != 1 {
			return false, nil
		}
	}
	return true, nil
}

func windsurfManagedHookEntryMatches(raw interface{}, expected, goos string) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok || entry["show_output"] != true {
		return false
	}
	if goos == "windows" {
		command, ok := entry["powershell"].(string)
		if !ok || command != expected {
			return false
		}
		_, hasFallback := entry["command"]
		_, hasBash := entry["bash"]
		return !hasFallback && !hasBash
	}
	command, ok := entry["command"].(string)
	if !ok || command != shellWord(expected) {
		return false
	}
	_, hasPowerShell := entry["powershell"]
	return !hasPowerShell
}

// openCodeManagedPluginPresent validates the standalone JavaScript artifact
// that OpenCode auto-loads. It deliberately does not route .js through the
// generic JSON/YAML/TOML hook-config parser: the managed-file receipt is the
// ownership and digest authority for this whole-file plugin.
func openCodeManagedPluginPresent(conn Connector, opts SetupOpts) (bool, error) {
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) != 1 {
		return false, fmt.Errorf("opencode managed plugin path count is %d; want 1", len(paths))
	}
	path := paths[0]
	backup, err := loadManagedFileBackupPath(
		managedFileBackupPath(opts.DataDir, "opencode", "config"),
	)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("load opencode managed plugin receipt: %w", err)
	}
	boundPath, err := validateManagedFileBackupTarget(backup, "opencode", "config", path)
	if err != nil {
		return false, fmt.Errorf("validate opencode managed plugin receipt: %w", err)
	}
	if err := safefile.ValidatePrivateFile(boundPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("validate opencode managed plugin protection: %w", err)
	}
	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return false, fmt.Errorf("read opencode managed plugin: %w", err)
	}
	if info == nil || !managedFileBackupMatchesSnapshot(&backup, data, true) {
		return false, nil
	}
	for _, marker := range [][]byte{
		[]byte("// defenseclaw-managed-plugin v7"),
		[]byte(`"/api/v1/opencode/hook"`),
		[]byte(`"tool.execute.before": async`),
		[]byte(`if (verdict && verdict.reason) throw new Error(verdict.reason);`),
		[]byte(`verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE`),
		[]byte(`hook_event_name: "defenseclaw.plugin.loaded"`),
		[]byte(`"tool.execute.after": async`),
		[]byte(`input && input.args`),
		[]byte(`payload.tool_result = toolResult`),
	} {
		if !bytes.Contains(data, marker) {
			return false, nil
		}
	}
	return true, nil
}

// configFileReferencesHook reports whether the file at path contains any of
// the owned hook command needles. A missing file reports false (not present)
// rather than an error: a deleted connector config is exactly the tamper case
// the guard re-installs. Any other read error is surfaced so the guard can log
// and skip rather than heal on incomplete information.
func configFileReferencesHook(path string, needles []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var decoded interface{}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return false, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &decoded); err != nil {
			return false, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	case ".toml":
		if err := toml.Unmarshal(data, &decoded); err != nil {
			return false, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	}
	if decoded != nil {
		return structuredHookCommandReferences(decoded, needles), nil
	}
	return false, nil
}

func structuredHookCommandReferences(raw interface{}, needles []string) bool {
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if structuredHookCommandReferences(item, needles) {
				return true
			}
		}
	case map[string]interface{}:
		if structuredNativeExecHookReferences(value, needles) {
			return true
		}
		for key, item := range value {
			if key == "command" || key == "bash" || key == "handler" || key == "powershell" {
				command := strings.TrimSpace(stringValue(item))
				for _, needle := range needles {
					needle = strings.TrimSpace(needle)
					if needle != "" && hookCommandMatches(command, needle) {
						return true
					}
				}
			}
			if structuredHookCommandReferences(item, needles) {
				return true
			}
		}
	}
	return false
}

func structuredNativeExecHookReferences(entry map[string]interface{}, needles []string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	command := strings.TrimSpace(stringValue(entry["command"]))
	if command == "" || !isDefenseClawManagedHookExecutable(command) {
		return false
	}
	rawArgs, ok := entry["args"].([]interface{})
	if !ok || len(rawArgs) != 3 {
		return false
	}
	args := make([]string, len(rawArgs))
	for i, raw := range rawArgs {
		arg, ok := raw.(string)
		if !ok {
			return false
		}
		args[i] = arg
	}
	if args[0] != "hook" || args[1] != "--connector" || strings.TrimSpace(args[2]) == "" {
		return false
	}
	marker := nativeHookFlag + args[2]
	for _, needle := range needles {
		if strings.Contains(strings.TrimSpace(needle), marker) {
			return true
		}
	}
	return false
}

func stringValue(value interface{}) string {
	text, _ := value.(string)
	return text
}

func hookCommandMatches(command, needle string) bool {
	if strings.HasPrefix(needle, nativeHookFlag) {
		connectorName := strings.TrimSpace(strings.TrimPrefix(needle, nativeHookFlag))
		return connectorName != "" && command == hookInvocationCommandFor("windows", connectorName, "")
	}
	return command == needle || command == shellWord(needle)
}
