// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if conn.Name() == "deepseek" {
		return []string{deepseekHooksPath(opts), deepseekPatchPath(opts)}
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
//     Cursor is matched exactly because its native transport requires a
//     generated PowerShell adapter. Antigravity is also matched
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
		case "deepseek":
			return []string{shellSingleQuote(hookScript)}
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
		if conn.Name() == "cursor" {
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

type ownedHookContractContextInspector interface {
	ownedHookContractPresentContext(context.Context, SetupOpts) (bool, error)
}

func OwnedHooksPresent(conn Connector, opts SetupOpts) (bool, error) {
	return OwnedHooksPresentContext(context.Background(), conn, opts)
}

// OwnedHooksPresentContext is the cancellable form used by managed guardians
// when a connector's effective policy check may perform bounded external work.
func OwnedHooksPresentContext(ctx context.Context, conn Connector, opts SetupOpts) (bool, error) {
	if inspector, ok := conn.(ownedHookContractContextInspector); ok {
		return inspector.ownedHookContractPresentContext(ctx, opts)
	}
	if cursor, ok := conn.(*hookOnlyConnector); ok && cursor.name == "cursor" {
		return cursor.ownedCursorHookContractPresent(opts)
	}
	if conn != nil && conn.Name() == "devin" {
		devin, ok := conn.(*hookOnlyConnector)
		if !ok {
			return false, errors.New("devin hook contract requires the native Devin connector")
		}
		return devinOwnedHooksPresent(devin, opts)
	}
	// OpenCode is a whole-file managed plugin. Its generic hook-only marker
	// inspector proves only the embedded version header; the custody receipt is
	// the authority for the exact path and post-setup digest, so evaluate it
	// before the hookOnlyConnector interface case below.
	if conn != nil && conn.Name() == "opencode" {
		return openCodeManagedPluginPresent(conn, opts)
	}
	if inspector, ok := conn.(ownedHookContractInspector); ok {
		return inspector.ownedHookContractPresent(opts)
	}
	return ownedHooksPresentInConfig(conn, opts)
}

func ownedHooksPresentInConfig(conn Connector, opts SetupOpts) (bool, error) {
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
	if err := validateOpenCodeManagedPluginProtection(boundPath, opts); err != nil {
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
	markers := [][]byte{
		[]byte("// defenseclaw-managed-plugin v7"),
		[]byte(`"/api/v1/opencode/hook"`),
		[]byte(`"tool.execute.before": async`),
		openCodePluginBlockThrow(opts, "verdict.reason", "verdict && verdict.reason"),
		[]byte(`verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE`),
		[]byte(`hook_event_name: "defenseclaw.plugin.loaded"`),
		[]byte(`"tool.execute.after": async`),
		[]byte(`input && input.args`),
		[]byte(`payload.tool_result = toolResult`),
	}
	if guard := managedPluginForeignHookGuardMarker(opts, "const DC_FOREIGN_GUARD = ", ";\n"); guard != nil {
		markers = append(markers, guard, openCodePluginBlockThrow(opts, "blocked", "blocked"))
	}
	// A plugin rendered before the listener proof existed would still send
	// its credential to whoever holds the TCP port; it is repaired.
	if managedPluginListenerProof(opts) {
		markers = append(markers,
			[]byte("const DC_LISTENER_PROOF = \"1\";\n"),
			[]byte("if (DC_LISTENER_PROOF) await defenseclawProveListener(token, init.signal);"),
		)
	}
	for _, marker := range markers {
		if !bytes.Contains(data, marker) {
			return false, nil
		}
	}
	return true, nil
}

// openCodePluginBlockThrow is the rendered statement that fails a blocked
// tool call: the plain block error, also shown as an error notice
// (defenseclawBlock), in per-user and standalone renders, and the reason
// alone in the Secure Client render. A plugin rendered before the block
// notice existed is repaired.
func openCodePluginBlockThrow(opts SetupOpts, reason, condition string) []byte {
	if pluginSecureClientProfile(opts) {
		return []byte("if (" + condition + ") throw new Error(" + reason + ");")
	}
	return []byte("if (" + condition + ") throw defenseclawBlock(client, " + reason + ");")
}

// validateOpenCodeManagedPluginProtection checks the plugin's custody. A
// setup for the current user requires the safefile owner-private shape for
// that user. A Windows enterprise guardian verifying a per-user target
// (ManagedTargetSID) runs as LocalSystem or an administrator without that
// user's token, so the current-user shape cannot apply; the guardian pins the
// exact managed plugin DACL itself, and here the plugin needs the same custody
// Amp's plugin does: an owner trusted for the target account and no untrusted
// write authority on the file or its directory.
func validateOpenCodeManagedPluginProtection(path string, opts SetupOpts) error {
	if strings.TrimSpace(opts.ManagedTargetSID) != "" {
		return validatePluginArtifactDestinationFor(path, opts.ManagedTargetSID)
	}
	return safefile.ValidatePrivateFile(path)
}

// readHookConfigFile reads a vendor hook config. The file is opened without
// blocking and must be a regular file (a symlink to one is still followed),
// so a named pipe or device in its place is reported by path instead of
// stalling the per-user worker until its deadline.
func readHookConfigFile(path string) ([]byte, error) {
	file, err := openHookConfigForRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is %s, not a regular file; replace it with a regular file", path, hookConfigFileKind(info.Mode()))
	}
	return io.ReadAll(file)
}

func hookConfigFileKind(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	default:
		return "a special file"
	}
}

// OwnedHookConfigReferences returns the hook config files of conn that still
// reference DefenseClaw's own hook commands for opts. After a teardown it
// names a registration the teardown left, for example one its restore of the
// pre-setup file brought back.
func OwnedHookConfigReferences(conn Connector, opts SetupOpts) ([]string, error) {
	needles := ownedHookCommandNeedles(opts, conn)
	if len(needles) == 0 {
		return nil, nil
	}
	var remaining []string
	for _, path := range HookConfigPathsForConnector(conn, opts) {
		present, err := configFileReferencesHook(path, needles)
		if err != nil {
			return remaining, err
		}
		if present {
			remaining = append(remaining, path)
		}
	}
	return remaining, nil
}

// configFileReferencesHook reports whether the file at path contains any of
// the owned hook command needles. A missing file reports false (not present)
// rather than an error: a deleted connector config is exactly the tamper case
// the guard re-installs. Any other read error is surfaced so the guard can log
// and skip rather than heal on incomplete information.
func configFileReferencesHook(path string, needles []string) (bool, error) {
	data, err := readHookConfigFile(path)
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
