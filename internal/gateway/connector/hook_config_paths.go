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
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
// A registration that still holds an edited DefenseClaw entry next to the
// working set is not present either (ownedHookConfigHoldsEditedEntry).
func OwnedHooksPresentContext(ctx context.Context, conn Connector, opts SetupOpts) (bool, error) {
	present, err := ownedHookRegistrationPresent(ctx, conn, opts)
	if err != nil || !present {
		return present, err
	}
	return !ownedHookConfigHoldsEditedEntry(conn, opts), nil
}

func ownedHookRegistrationPresent(ctx context.Context, conn Connector, opts SetupOpts) (bool, error) {
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
	if hookOnly, ok := conn.(*hookOnlyConnector); ok && hookOnly.rendersExactHookEntries() {
		for _, path := range paths {
			decoded, err := decodeHookConfigFile(path)
			if err != nil {
				return false, err
			}
			document, _ := decoded.(map[string]interface{})
			if !hookOnly.renderedHookEntriesPresent(opts, document) {
				return false, nil
			}
		}
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
	decoded, err := decodeHookConfigFile(path)
	if err != nil || decoded == nil {
		return false, err
	}
	return structuredHookCommandReferences(decoded, needles), nil
}

// decodeHookConfigFile parses the JSON, YAML or TOML hook config at path. A
// missing file, or one of another kind (a JavaScript plugin), decodes to nil.
func decodeHookConfigFile(path string) (interface{}, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var decoded interface{}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	case ".toml":
		if err := ParseCodexTOML(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	}
	return decoded, nil
}

// rendersExactHookEntries reports whether conn's presence check compares its
// hook config entry by entry with what Setup renders
// (renderedHookEntriesPresent). Matching any one owned command was not
// enough: with one of Hermes' 23 entries (or one Copilot event) edited, the
// other 22 still matched, so the hook guard never repaired the file and the
// edited event ran unguarded (GAP-0906).
func (c *hookOnlyConnector) rendersExactHookEntries() bool {
	switch c.name {
	case "hermes", "copilot", "antigravity":
		return true
	}
	return false
}

// renderedHookEntriesPresent reports whether document holds exactly the hook
// entries Setup renders for c: each event's entry once, built by the same
// functions Setup writes with, and no other entry that Setup's reconcile
// claims as DefenseClaw's (an edited script path or name, a misplaced or
// duplicate entry). Entries Setup does not claim, the user's own hooks, are
// ignored. Every entry that fails the check is one Setup replaces, so a heal
// always converges.
func (c *hookOnlyConnector) renderedHookEntriesPresent(opts SetupOpts, document map[string]interface{}) bool {
	if document == nil {
		return false
	}
	hookCommand := c.hookCommand(opts)
	hooks, _ := document["hooks"].(map[string]interface{})
	switch c.name {
	case "hermes":
		command := hermesConfiguredHookCommand(hookCommand, opts.HookExecutable)
		recognized := hermesRecognizedHookCommands(command)
		want := make(map[string]interface{}, len(hermesRequiredHooks))
		for _, spec := range hermesRequiredHooks {
			want[spec.event] = hermesHookEntry(command, spec.matcher)
		}
		return hookEventEntriesMatch(hooks, want, func(_ string, entry interface{}) bool {
			command, _ := hermesHookEntryCommand(entry)
			return hermesReplaceableHookCommand(command, recognized)
		})
	case "copilot":
		events := c.copilotHookEvents(opts)
		want := make(map[string]interface{}, len(events))
		for _, event := range events {
			want[event] = copilotHookRegistration(runtime.GOOS, event, hookCommand)
		}
		edited := hookScriptBaseName(hookCommand)
		return hookEventEntriesMatch(hooks, want, func(event string, entry interface{}) bool {
			if _, registered := want[event]; registered {
				return managedHookCommandEntry(entry, hookCommand) || editedDefenseClawHookEntry(entry, edited)
			}
			return slices.Contains(copilotCurrentHookEvents, event) &&
				(containsHookScript(entry, hookCommand) || editedDefenseClawHookEntry(entry, edited))
		})
	case "antigravity":
		// Setup rewrites each DefenseClaw-owned outer key whole.
		for key, rendered := range antigravityOwnedHookKeys(runtime.GOOS, hookCommand) {
			if !sameHookJSON(document[key], rendered) {
				return false
			}
		}
		return true
	}
	return false
}

// hookEventEntriesMatch checks an agent's event -> handler-list hook map
// against the entries Setup renders (want): every event in want holds its
// entry exactly once, and no event holds another entry claims marks as
// DefenseClaw's.
func hookEventEntriesMatch(
	hooks map[string]interface{},
	want map[string]interface{},
	claims func(event string, entry interface{}) bool,
) bool {
	for event, rendered := range want {
		entries, ok := hooks[event].([]interface{})
		if !ok {
			return false
		}
		exact := 0
		for _, entry := range entries {
			if exact == 0 && sameHookJSON(entry, rendered) {
				exact++
				continue
			}
			if claims(event, entry) {
				return false
			}
		}
		if exact != 1 {
			return false
		}
	}
	for event, raw := range hooks {
		if _, registered := want[event]; registered {
			continue
		}
		entries, ok := raw.([]interface{})
		if !ok {
			entries = []interface{}{raw}
		}
		for _, entry := range entries {
			if claims(event, entry) {
				return false
			}
		}
	}
	return true
}

// sameHookJSON compares a decoded hook entry with a rendered one by their
// JSON form, so a YAML int, a JSON number and a Go int of the same value are
// equal.
func sameHookJSON(left, right interface{}) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// ownedHookConfigHoldsEditedEntry reports whether one of conn's hook config
// files holds a DefenseClaw hook entry whose script path was edited (its
// script name, hook directory or data directory) next to the working set.
// The agent runs that entry too, and it fails on every call: Copilot denied
// every tool call, Claude Code blocked every prompt (GAP-0906, GAP-0907).
// Setup's reconcile replaces such an entry, so reporting the registration
// absent lets the hook guard heal the file within seconds. Windows registers
// native launcher commands, which never have the edited-script shape.
func ownedHookConfigHoldsEditedEntry(conn Connector, opts SetupOpts) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	owner, ok := conn.(HookScriptOwner)
	if !ok {
		return false
	}
	for _, configPath := range HookConfigPathsForConnector(conn, opts) {
		decoded, err := decodeHookConfigFile(configPath)
		if err != nil || decoded == nil {
			// The connector's own check already read this file.
			continue
		}
		for _, name := range owner.HookScriptNames(opts) {
			if hookDocumentHoldsEditedEntry(decoded, opts.DataDir, name) {
				return true
			}
		}
	}
	return false
}

// hookDocumentHoldsEditedEntry is the rule the doctor's edited_hook_problems
// applies (cli/defenseclaw/hook_integrity.py; both read
// testdata/hook_edited_entries.json): a command or bash string whose script
// word has DefenseClaw's hook shape for scriptName
// (editedDefenseClawHookCommand), lies under the data directory's parent and
// is not the script Setup registers. Claude Code's missing-script guard is
// unwrapped first.
func hookDocumentHoldsEditedEntry(document interface{}, dataDir, scriptName string) bool {
	dataDir = filepath.ToSlash(filepath.Clean(dataDir))
	current := path.Join(dataDir, "hooks", scriptName)
	home := strings.TrimSuffix(path.Dir(dataDir), "/") + "/"
	for _, command := range hookCommandStrings(document) {
		command = claudeCodeUnguardedHookCommand(strings.TrimSpace(command))
		if !editedDefenseClawHookCommand(command, scriptName) {
			continue
		}
		if word, _, ok := posixHookCommandSplit(command); ok && word != current && strings.HasPrefix(word, home) {
			return true
		}
	}
	return false
}

// hookCommandStrings returns every string under a command or bash key of a
// decoded hook config.
func hookCommandStrings(raw interface{}) []string {
	var found []string
	switch value := raw.(type) {
	case map[string]interface{}:
		for key, item := range value {
			if command, ok := item.(string); ok && (key == "command" || key == "bash") {
				found = append(found, command)
				continue
			}
			found = append(found, hookCommandStrings(item)...)
		}
	case []interface{}:
		for _, item := range value {
			found = append(found, hookCommandStrings(item)...)
		}
	}
	return found
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
	// A per-user Claude Code handler runs the launcher through the cmd.exe
	// guard (GAP-1091); an exact generated guard reads as the exec form it runs.
	if view, ok := claudeCodeExecView(entry).(map[string]interface{}); ok {
		entry = view
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
