// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The foreign-hook guard exists because several agents run every
// registered hook or plugin and let any of them rewrite a tool call's input
// (Claude/Codex/Devin updatedInput, Cursor updated_input, Copilot
// modifiedArgs, OpenCode tool.execute.before, a Hermes pre_tool_call shell
// hook) or approve it after
// DefenseClaw inspected the original. Where the vendor has no
// managed-hooks-only lock, a standard user (or a prompt-injected agent)
// could otherwise add such a hook and run something DefenseClaw never saw.
//
// Two enforcement points share this scanner:
//   - the admin-owned hook binary evaluates user and project hook files on
//     every call and fails closed while an unapproved foreign hook exists;
//   - the guardian removes foreign entries from user-level vendor config
//     (backing them up and auditing each removal). Project files are never
//     rewritten; they are reported and blocked.

// Scopes.
const (
	ScopeUser    = "user"
	ScopeProject = "project"
)

// Source formats.
const (
	formatGrouped     = "grouped"      // Claude-style {"hooks":{event:[{matcher,hooks:[handler]}]}}
	formatHooksObject = "hooks-object" // Devin hooks.v1.json: the whole file is the hooks object
	formatFlat        = "flat"         // Cursor/Copilot {"hooks":{event:[handler]}}
	formatFlatDir     = "flat-dir"     // directory of flat JSON files
	formatCodexTOML   = "codex-toml"   // Codex config.toml [[hooks.<event>]]
	formatPluginDir   = "plugin-dir"   // directory of plugin source files
	formatPluginList  = "plugin-list"  // JSON "plugin" array (OpenCode)
	// formatClaudePlugins is a Claude settings file whose enabledPlugins
	// name installed plugins; each enabled plugin's hooks are scanned.
	formatClaudePlugins = "claude-plugins"
)

// guardFileLimit bounds every user or project hook file the guard reads.
const guardFileLimit = 1 << 20

// maxProjectWalk bounds the ancestor walk from the working directory. A
// deeper path fails closed instead of silently skipping the directories
// above it (agents resolve project config up to the repository root).
const maxProjectWalk = 256

// hookSource is one user or project file (or directory) to scan. A source
// with err set could not be resolved and is reported as unverifiable. base
// is the directory a relative hook command resolves against (the project
// root, or the home for a user source) and home the user's home.
type hookSource struct {
	scope  string
	path   string
	format string
	err    error
	base   string
	home   string
	sourceOptions
}

// sourceOptions are per-source exceptions to the defaults.
type sourceOptions struct {
	// limit overrides guardFileLimit for a file an agent shares with other
	// state (~/.claude.json).
	limit int64
	// reportOnly keeps the cleanup from rewriting the file (another
	// program owns and rewrites it); its findings are reported.
	reportOnly bool
	// inline is a source the agent reads from its environment
	// (OPENCODE_CONFIG_CONTENT); path is a label.
	inline []byte
}

// child returns a source for an entry inside s (a flat hook directory or a
// plugin directory), keeping its scope and resolution directories.
func (s hookSource) child(path, format string) hookSource {
	return hookSource{scope: s.scope, path: path, format: format, base: s.base, home: s.home}
}

// guardLargeFileLimit bounds a user file an agent shares with its own
// state (~/.claude.json grows with project history).
const guardLargeFileLimit = 32 << 20

// Finding is one foreign hook entry or plugin.
type Finding struct {
	Connector string `json:"connector"`
	Scope     string `json:"scope"`
	Path      string `json:"path"`
	Event     string `json:"event,omitempty"`
	Command   string `json:"command,omitempty"`
	Digest    string `json:"digest"`
	Reason    string `json:"reason,omitempty"`
	Allowed   bool   `json:"allowed"`
	// key locates the entry inside its document for the cleanup (the
	// entry's own canonical form, independent of what it references).
	key string
}

// GuardRequest describes one scan.
type GuardRequest struct {
	Connector string
	GOOS      string
	Home      string
	// Homes are further homes the agent may read user config from (the
	// home its environment names when that differs from the account's).
	Homes      []string
	WorkingDir string
	// WorkingDirs are further directories the agent may load project config
	// from (payload cwd and workspace roots). Every home and working
	// directory is scanned in one pass; a path is read once.
	WorkingDirs []string
	// AccountHome is the account's home from the system account database
	// (never the agent's environment); DefenseClaw's per-user plugin is
	// recognized only there, and only on a per-user route.
	AccountHome string
	HookBinary  string
	Policy      PublicConnectorPolicy
	// Getenv returns the agent's environment (vendor config-dir overrides).
	Getenv func(string) string
	// OwnedCommands are the exact commands of DefenseClaw's own per-user
	// registration (connector.PerUserOwnedHookCommands) under the account's
	// home from the system account database, never under a directory the
	// agent's environment names. They name user-owned scripts, so they are
	// honored only for a connector whose route is per-user (where that
	// registration is DefenseClaw's hook and the guardian repairs it); on a
	// machine-policy connector the same command is foreign.
	OwnedCommands []string
	// Deadline bounds the scan (zero: none). Past it, and past the scan's
	// file, byte and directory-entry budgets, the scan stops with an
	// unverifiable finding, so a slow or flooded tree fails closed instead
	// of outliving the agent's hook timeout.
	Deadline time.Time
	// StopAtFirstBlocking ends a remove-mode evaluation at the first
	// unapproved finding; the hook needs only the decision.
	StopAtFirstBlocking bool
}

// Scan budgets. Real hook trees are a few small files.
const (
	guardDirEntryLimit = 256
	guardScanFileLimit = 512
	guardScanByteLimit = 64 << 20
)

// GuardDecision is the scan result.
type GuardDecision struct {
	Findings []Finding `json:"findings"`
	Deny     bool      `json:"deny"`
	Reason   string    `json:"reason,omitempty"`
	// Incomplete is set when the scan stopped on its file, byte,
	// referenced-path or time budget before it reached every source, so a
	// source the agent loaded may not have been checked. At a session start
	// it blocks the session (ApplyForeignHookSession).
	Incomplete bool `json:"incomplete,omitempty"`
}

func (r GuardRequest) getenv(key string) string {
	if r.Getenv == nil {
		return ""
	}
	return strings.TrimSpace(r.Getenv(key))
}

func (r GuardRequest) goos() string {
	if r.GOOS != "" {
		return r.GOOS
	}
	return runtimeGOOS()
}

// homes returns Home and Homes, absolute and distinct.
func (r GuardRequest) homes() []string {
	return distinctAbsPaths(append([]string{r.Home}, r.Homes...))
}

// workingDirs returns WorkingDir and WorkingDirs, absolute and distinct.
func (r GuardRequest) workingDirs() []string {
	return distinctAbsPaths(append([]string{r.WorkingDir}, r.WorkingDirs...))
}

func distinctAbsPaths(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !filepath.IsAbs(value) {
			continue
		}
		out = appendDistinctPath(out, filepath.Clean(value))
	}
	return out
}

// projectDirs returns the working directory and its ancestors up to the
// git root, including the user's home when the walk reaches it (an agent
// started in the home treats it as the project, and a repository may be
// rooted there). The filesystem root is included only when volumeRoot is
// set (Windows): a Unix / is root-owned, but standard users may create
// directories such as C:\.cursor in a Windows drive root, and an agent
// started in C:\ (or in a repository rooted there) loads them. A symlinked
// working directory is walked both as given and resolved, because agents
// locate the repository root through either. The walk has no silent depth
// cap: past maxProjectWalk directories it returns an error so the guard
// fails closed.
func projectDirs(workingDir string, homes []string, volumeRoot bool) ([]string, error) {
	if strings.TrimSpace(workingDir) == "" {
		return nil, nil
	}
	starts := []string{filepath.Clean(workingDir)}
	if resolved := resolvedPath(starts[0]); !samePath(resolved, starts[0]) {
		starts = append(starts, resolved)
	}
	// A home is recognized under its given and its resolved spelling
	// (macOS temporary and some network homes sit behind a symlink).
	var homeKeys []string
	for _, home := range homes {
		homeKeys = appendDistinctPath(appendDistinctPath(homeKeys, home), resolvedPath(home))
	}
	isHome := func(dir string) bool {
		for _, home := range homeKeys {
			if samePath(dir, home) {
				return true
			}
		}
		return false
	}
	// A directory reached under two spellings (the given and the resolved
	// walk) is scanned once, under the first.
	var dirs, seen []string
	for _, dir := range starts {
		for depth := 0; ; depth++ {
			if depth >= maxProjectWalk {
				return dirs, fmt.Errorf("%s is more than %d directories deep; the repository root cannot be found", starts[0], maxProjectWalk)
			}
			parent := filepath.Dir(dir)
			atRoot := parent == dir
			if atRoot && !volumeRoot {
				break
			}
			if key := resolvedPath(dir); !containsPath(seen, key) {
				seen = append(seen, key)
				dirs = append(dirs, dir)
			}
			if atRoot || isHome(dir) {
				break
			}
			if info, err := os.Lstat(filepath.Join(dir, ".git")); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
				break
			}
			dir = parent
		}
	}
	return dirs, nil
}

// resolvedPath is path with symlinks resolved, or path itself when it
// cannot be resolved.
func resolvedPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(path)
}

// samePath compares cleaned paths the way the host filesystem does.
func samePath(a, b string) bool {
	if runtimeGOOS() == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func appendDistinctPath(list []string, value string) []string {
	for _, existing := range list {
		if samePath(existing, value) {
			return list
		}
	}
	return append(list, value)
}

// guardSources lists every user and project location for connector. User
// sources come first and a path listed twice (a project source in the home
// directory that is also a user source) is kept once, as a user source.
func guardSources(req GuardRequest) []hookSource {
	var userSources, projectSources []hookSource
	homes := req.homes()
	var projects []string
	for _, workingDir := range req.workingDirs() {
		dirs, walkErr := projectDirs(workingDir, homes, req.goos() == "windows")
		for _, dir := range dirs {
			projects = appendDistinctPath(projects, dir)
		}
		if walkErr != nil {
			projectSources = append(projectSources, hookSource{scope: ScopeProject, path: workingDir, err: walkErr})
		}
	}
	firstHome := ""
	if len(homes) > 0 {
		firstHome = homes[0]
	}
	project := func(format string, rel ...string) {
		for _, dir := range projects {
			projectSources = append(projectSources, hookSource{scope: ScopeProject, path: filepath.Join(append([]string{dir}, rel...)...), format: format, base: dir, home: firstHome})
		}
	}
	user := func(home string, options sourceOptions, format string, parts ...string) {
		userSources = append(userSources, hookSource{scope: ScopeUser, path: filepath.Join(parts...), format: format, base: home, home: home, sourceOptions: options})
	}
	if len(homes) == 0 {
		connectorSources(req, "", func(string, sourceOptions, string, ...string) {}, project)
	}
	for i, home := range homes {
		projectOnce := project
		if i > 0 {
			projectOnce = func(string, ...string) {}
		}
		connectorSources(req, home, user, projectOnce)
	}
	var sources []hookSource
	type sourceKey struct{ path, format string }
	seen := []sourceKey{}
	for _, source := range append(userSources, projectSources...) {
		key := sourceKey{filepath.Clean(source.path), source.format}
		duplicate := false
		for _, existing := range seen {
			if existing.format == key.format && samePath(existing.path, key.path) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seen = append(seen, key)
		sources = append(sources, source)
	}
	return sources
}

// connectorSources adds connector's user sources under home (none when
// home is empty) and its project-relative sources.
func connectorSources(req GuardRequest, home string, addUser func(home string, options sourceOptions, format string, parts ...string), project func(format string, parts ...string)) {
	userWith := func(options sourceOptions, format string, parts ...string) {
		if home == "" {
			return
		}
		addUser(home, options, format, parts...)
	}
	user := func(format string, parts ...string) { userWith(sourceOptions{}, format, parts...) }
	// envPath resolves a path an environment variable names; a relative one
	// is relative to the agent's working directory.
	envPath := func(key string) string {
		value := req.getenv(key)
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		if dirs := req.workingDirs(); len(dirs) > 0 {
			return filepath.Join(dirs[0], value)
		}
		return ""
	}
	xdgConfig := req.getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	// Cursor, Copilot and Devin also load Claude-format hook files by
	// default (third-party extensibility), so those run inside the agent too.
	claudeFormat := func(includeUser bool) {
		if includeUser {
			user(formatGrouped, home, ".claude", "settings.json")
		}
		project(formatGrouped, ".claude", "settings.json")
		project(formatGrouped, ".claude", "settings.local.json")
	}
	switch req.Connector {
	case ConnectorCursor:
		user(formatFlat, home, ".cursor", "hooks.json")
		project(formatFlat, ".cursor", "hooks.json")
		claudeFormat(true)
	case ConnectorCopilot:
		copilotHome := req.getenv("COPILOT_HOME")
		if copilotHome == "" {
			copilotHome = filepath.Join(home, ".copilot")
		}
		user(formatFlatDir, copilotHome, "hooks")
		user(formatFlat, copilotHome, "settings.json")
		project(formatFlatDir, ".github", "hooks")
		project(formatFlat, ".github", "copilot", "settings.json")
		project(formatFlat, ".github", "copilot", "settings.local.json")
		claudeFormat(false)
	case "devin":
		if req.goos() == "windows" {
			// APPDATA as the agent sees it, and the profile's default
			// roaming folder (the guardian's cleanup has no user
			// environment).
			if appData := req.getenv("APPDATA"); appData != "" {
				user(formatGrouped, appData, "devin", "config.json")
			}
			user(formatGrouped, home, "AppData", "Roaming", "devin", "config.json")
		} else {
			user(formatGrouped, xdgConfig, "devin", "config.json")
		}
		// Devin also reads hooks from ~/.claude.json. Claude Code owns and
		// rewrites that file, so the cleanup reports rather than rewrites.
		userWith(sourceOptions{limit: guardLargeFileLimit, reportOnly: true}, formatGrouped, home, ".claude.json")
		user(formatGrouped, home, ".claude", "settings.local.json")
		project(formatHooksObject, ".devin", "hooks.v1.json")
		project(formatGrouped, ".devin", "config.json")
		project(formatGrouped, ".devin", "config.local.json")
		claudeFormat(true)
		for _, store := range devinPluginStores(req, home) {
			user(formatDevinPlugins, store)
		}
	case ConnectorClaudeCode:
		claudeDir := req.getenv("CLAUDE_CONFIG_DIR")
		if claudeDir == "" {
			claudeDir = filepath.Join(home, ".claude")
		}
		user(formatGrouped, claudeDir, "settings.json")
		project(formatGrouped, ".claude", "settings.json")
		project(formatGrouped, ".claude", "settings.local.json")
		// Plugins enabled in those settings run their own hooks.
		user(formatClaudePlugins, claudeDir, "settings.json")
		project(formatClaudePlugins, ".claude", "settings.json")
		project(formatClaudePlugins, ".claude", "settings.local.json")
	case ConnectorCodex:
		codexHome := req.getenv("CODEX_HOME")
		if codexHome == "" {
			codexHome = filepath.Join(home, ".codex")
		}
		user(formatCodexTOML, codexHome, "config.toml")
		user(formatGrouped, codexHome, "hooks.json")
		project(formatCodexTOML, ".codex", "config.toml")
		project(formatGrouped, ".codex", "hooks.json")
	case "opencode":
		// Global config (opencode.json, opencode.jsonc, legacy config.json)
		// and plugin directories, OPENCODE_CONFIG, OPENCODE_CONFIG_DIR
		// (searched like a .opencode directory) and OPENCODE_CONFIG_CONTENT.
		user(formatPluginDir, xdgConfig, "opencode", "plugins")
		user(formatPluginDir, xdgConfig, "opencode", "plugin")
		user(formatPluginList, xdgConfig, "opencode", "opencode.json")
		user(formatPluginList, xdgConfig, "opencode", "opencode.jsonc")
		user(formatPluginList, xdgConfig, "opencode", "config.json")
		if custom := envPath("OPENCODE_CONFIG"); custom != "" {
			user(formatPluginList, custom)
		}
		if dir := envPath("OPENCODE_CONFIG_DIR"); dir != "" {
			user(formatPluginDir, dir, "plugins")
			user(formatPluginDir, dir, "plugin")
			user(formatPluginList, dir, "opencode.json")
			user(formatPluginList, dir, "opencode.jsonc")
		}
		if content := req.getenv("OPENCODE_CONFIG_CONTENT"); content != "" {
			userWith(sourceOptions{inline: []byte(content), reportOnly: true}, formatPluginList, "$OPENCODE_CONFIG_CONTENT")
		}
		project(formatPluginDir, ".opencode", "plugins")
		project(formatPluginDir, ".opencode", "plugin")
		project(formatPluginList, "opencode.json")
		project(formatPluginList, "opencode.jsonc")
		project(formatPluginList, ".opencode", "opencode.json")
		project(formatPluginList, ".opencode", "opencode.jsonc")
	case "amp":
		user(formatPluginDir, xdgConfig, "amp", "plugins")
		project(formatPluginDir, ".amp", "plugins")
	case ConnectorHermes:
		// User config only: Hermes reads shell hooks from no project file.
		hermesUserConfig(req, home, envPath, user)
	}
}

// ownedCommand reports whether command is one of the exact admin-binary
// registrations DefenseClaw renders or, for a per-user connector only,
// DefenseClaw's own per-user registration; anything else is foreign.
// Per-user scripts are user-owned code: on a machine-policy connector the
// guardian never repairs them, so a user could put any content behind the
// path (and an unmanaged install's leftover registration would run twice).
func (r GuardRequest) ownedCommand(command string) bool {
	command = strings.TrimSpace(command)
	if r.Policy.Route == RoutePerUser {
		for _, owned := range r.OwnedCommands {
			if owned != "" && command == owned {
				return true
			}
		}
	}
	return ownedCommand(command, r.HookBinary)
}

// ownedHandlerKeys are the only keys DefenseClaw's own handlers carry
// besides their command fields. Any other key (an OS-specific override, an
// environment block, a working directory, an http url, a prompt) can change
// what the agent runs, so a handler that carries one is foreign.
var ownedHandlerKeys = map[string]bool{
	"type":       true,
	"timeout":    true,
	"timeoutSec": true,
	"failClosed": true,
	"matcher":    true,
	"async":      true,
}

// handlerCommandKeys are the fields an agent may execute; each vendor runs
// a different one (Copilot bash on Unix and powershell on Windows, Claude
// http hooks url), so every one present must be owned.
var handlerCommandKeys = map[string]bool{"command": true, "bash": true, "powershell": true}

// ownedHandler reports whether handler is exactly one of DefenseClaw's own
// registrations: a command handler whose every executable field is an owned
// command and that carries no key DefenseClaw does not write.
func (r GuardRequest) ownedHandler(handler any) bool {
	var fields map[string]any
	switch v := handler.(type) {
	case *object:
		fields = v.values
	case map[string]any:
		fields = v
	default:
		return false
	}
	commands := 0
	for key, value := range fields {
		switch {
		case handlerCommandKeys[key]:
			command, ok := value.(string)
			if !ok || !r.ownedCommand(command) {
				return false
			}
			commands++
		case key == "type":
			if kind, _ := value.(string); kind != "command" {
				return false
			}
		case key == "args":
			// Claude's Windows exec form: the admin binary in command with
			// its arguments listed separately.
			if !ownedExecArgs(value) || !strings.EqualFold(strings.TrimSpace(stringField(handler, "command")), strings.TrimSpace(r.HookBinary)) {
				return false
			}
		case !ownedHandlerKeys[key]:
			return false
		}
	}
	return commands > 0
}

// ownedExecArgs accepts only the managed invocation DefenseClaw renders:
// hook --connector <name> --enterprise-managed [--event <event>]. Any other
// argument list (an unmanaged invocation pointed at another gateway
// address, for example) is foreign.
func ownedExecArgs(value any) bool {
	list, ok := value.([]any)
	if !ok {
		return false
	}
	args := make([]string, 0, len(list))
	for _, item := range list {
		arg, ok := item.(string)
		if !ok {
			return false
		}
		args = append(args, arg)
	}
	switch {
	case len(args) == 4:
	case len(args) == 6 && args[4] == "--event" && validConnectorToken(args[5]):
	default:
		return false
	}
	return args[0] == "hook" && args[1] == "--connector" && validConnectorToken(args[2]) && args[3] == "--enterprise-managed"
}

func ownedCommand(command, hookBinary string) bool {
	if command == "" || hookBinary == "" {
		return false
	}
	// Windows exec-form handlers carry the binary alone in command.
	if strings.EqualFold(command, hookBinary) {
		return true
	}
	rest, ok := strings.CutPrefix(command, shellQuote(hookBinary)+" hook --connector ")
	if !ok {
		return false
	}
	// Any DefenseClaw connector registration of the admin binary is owned:
	// the binary is administrator-owned and only talks to the gateway.
	name, rest, _ := strings.Cut(rest, " ")
	if !validConnectorToken(name) {
		return false
	}
	if rest == "--enterprise-managed" {
		return true
	}
	event, ok := strings.CutPrefix(rest, "--enterprise-managed --event ")
	if !ok {
		return false
	}
	event = strings.TrimSuffix(strings.TrimPrefix(event, "'"), "'")
	return validConnectorToken(event)
}

func validConnectorToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// handlerDisplayKeys are the fields shown in a finding, in order.
var handlerDisplayKeys = []string{"command", "bash", "powershell", "url", "prompt"}

// handlerCommand describes what a foreign handler runs for the finding. A
// handler with more than one executable field names each, so the report
// shows the field the vendor actually runs.
func handlerCommand(handler any) string {
	var parts []string
	for _, key := range handlerDisplayKeys {
		if value := stringField(handler, key); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	switch len(parts) {
	case 0:
		return string(canonicalJSON(handler))
	case 1:
		_, value, _ := strings.Cut(parts[0], "=")
		return value
	}
	return strings.Join(parts, " ")
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// readGuardFile reads a user or project file without following links or
// blocking. Anything at the path that is not a regular file (a FIFO a
// background writer feeds, a device, a socket, a directory) exists but
// cannot be verified, so the guard and the cleanup fail closed on it.
func readGuardFile(path string) ([]byte, bool, error) {
	return readGuardFileLimit(path, guardFileLimit)
}

func readGuardFileLimit(path string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("%s is a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%s is not a regular file (%s)", path, info.Mode().Type())
	}
	file, err := openGuardFile(path)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, true, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, true, fmt.Errorf("%s changed while it was read", path)
	}
	data, err := readBounded(file, limit)
	return data, true, err
}

// readGuardDir lists a user or project directory without following links
// or blocking. A missing path does not exist; anything else at the path
// that is not a directory cannot be verified.
func readGuardDir(path string) ([]fs.DirEntry, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("%s is a symbolic link", path)
	}
	if !info.IsDir() {
		return nil, true, fmt.Errorf("%s is not a directory (%s)", path, info.Mode().Type())
	}
	dir, err := openGuardDir(path)
	if err != nil {
		return nil, true, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, true, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, true, nil
}

func findingFor(req GuardRequest, source hookSource, event, command string, digest string, reason string) Finding {
	finding := Finding{
		Connector: req.Connector,
		Scope:     source.scope,
		Path:      source.path,
		Event:     event,
		Command:   truncate(command, 160),
		Digest:    digest,
		Reason:    reason,
		key:       digest,
	}
	for _, allowed := range req.Policy.AllowedHooks {
		if allowed == digest {
			finding.Allowed = true
		}
	}
	return finding
}

// guardLimitError is a per-file, per-folder or per-plugin-tree limit the
// scan stopped on. Unlike a file that cannot be read or parsed, such a
// source can hold hooks past the limit that the agent still loaded, so a
// session start that meets one is incomplete (GuardDecision.Incomplete),
// like a stop on the scan's overall budget.
type guardLimitError struct{ err error }

func (e *guardLimitError) Error() string { return e.err.Error() }

func (e *guardLimitError) Unwrap() error { return e.err }

func guardLimit(format string, args ...any) error {
	return &guardLimitError{err: fmt.Errorf(format, args...)}
}

// isGuardLimit reports whether err is a limit stop (guardLimitError, or a
// file over its read limit).
func isGuardLimit(err error) bool {
	var limit *guardLimitError
	var read *readLimitError
	return errors.As(err, &limit) || errors.As(err, &read)
}

// unreadable is unreadableFinding for a source of this scan; a limit stop
// marks the scan as incomplete.
func (s *guardScan) unreadable(source hookSource, err error) Finding {
	if isGuardLimit(err) {
		s.limited = true
	}
	return unreadableFinding(s.req, source, err)
}

// unreadableFinding reports a source the guard cannot verify. It is never
// approvable: allowlisting "this path could not be read" would admit
// whatever the path later holds.
func unreadableFinding(req GuardRequest, source hookSource, err error) Finding {
	finding := findingFor(req, source, "", "", sha256Hex([]byte("unverifiable\x00"+source.path)), "cannot verify hook file: "+err.Error())
	finding.Allowed = false
	return finding
}

// handlerFinding reports a foreign hook handler. The approvable digest
// covers the event, the handler and the content of every file its command
// may name (resolved against the project root, the config file's
// directory, the home, the agent's working directory, the handler's cwd
// and any directory the command changes into), so an approval covers one
// reviewed hook and not any repository's script of the same name. A
// handler whose references cannot all be bound cannot be approved. key
// identifies the handler itself for the cleanup.
func (s *guardScan) handlerFinding(source hookSource, event string, handler any) Finding {
	dirs, problem := s.handlerDirs(handler, source)
	files, filesProblem := s.referencedFiles(handlerValues(handler), source, dirs)
	if problem == "" {
		problem = filesProblem
	}
	digest := sha256Hex(canonicalJSON(orderedFromMap(map[string]any{
		"event":   event,
		"handler": handler,
		"files":   files,
	})))
	finding := findingFor(s.req, source, event, handlerCommand(handler), digest, "")
	finding.key = sha256Hex(canonicalJSON(handler))
	if problem != "" {
		finding.Allowed = false
		finding.Reason = unapprovableReason + problem
	}
	return finding
}

// scanJSONHooks returns findings for a grouped or flat hooks document.
func (s *guardScan) scanJSONHooks(source hookSource, data []byte) []Finding {
	req := s.req
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	hooks := doc
	if source.format != formatHooksObject {
		hooksValue, _ := doc.get("hooks")
		hooks, _ = hooksValue.(*object)
	} else if nested, ok := doc.get("hooks"); ok {
		if nestedObject, ok := nested.(*object); ok {
			hooks = nestedObject
		}
	}
	if hooks == nil {
		return nil
	}
	var findings []Finding
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, _ := value.([]any)
		for _, item := range list {
			handlers := []any{item}
			if source.format == formatGrouped || source.format == formatHooksObject {
				handlers = handlersOf(item)
			}
			for _, handler := range handlers {
				if req.ownedHandler(handler) {
					continue
				}
				findings = append(findings, s.handlerFinding(source, event, handler))
			}
		}
	}
	return findings
}

func (s *guardScan) scanCodexTOML(source hookSource, data []byte) []Finding {
	req := s.req
	cfg := map[string]any{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	var findings []Finding
	for _, event := range events {
		list, ok := hooks[event].([]any)
		if !ok {
			continue
		}
		for _, group := range list {
			for _, handler := range handlersOf(group) {
				if req.ownedHandler(handler) {
					continue
				}
				findings = append(findings, s.handlerFinding(source, event, handler))
			}
		}
	}
	return findings
}

// ownedPluginPath is where the guardian installs DefenseClaw's per-user
// plugin for connector under the account's home. It is DefenseClaw's only
// on a per-user route; a file of the same name anywhere else (a project, a
// different user directory, a plugin-list entry naming another path) is
// foreign.
func (r GuardRequest) ownedPluginPath(path string) bool {
	if r.Policy.Route != RoutePerUser || strings.TrimSpace(r.AccountHome) == "" || !filepath.IsAbs(r.AccountHome) {
		return false
	}
	var owned string
	switch r.Connector {
	case "amp":
		owned = filepath.Join(r.AccountHome, ".config", "amp", "plugins", "defenseclaw.ts")
	case ConnectorOpenCode:
		owned = filepath.Join(r.AccountHome, ".config", "opencode", "plugins", "defenseclaw.js")
	default:
		return false
	}
	return samePath(filepath.Clean(path), owned)
}

// guardScan reads user and project sources for one request under a shared
// budget. Once the deadline or a budget is exceeded every further read
// fails, and the scan records one unverifiable finding and stops.
type guardScan struct {
	req        GuardRequest
	files      int
	bytes      int64
	hashed     int64
	references int
	exceeded   error
	// limited is set when a source stopped on a per-file, per-folder or
	// per-plugin-tree limit (guardLimitError).
	limited bool
}

func newGuardScan(req GuardRequest) *guardScan { return &guardScan{req: req} }

func (s *guardScan) check() error {
	if s.exceeded != nil {
		return s.exceeded
	}
	switch {
	case !s.req.Deadline.IsZero() && time.Now().After(s.req.Deadline):
		s.exceeded = errors.New("the hook scan ran past its time limit")
	case s.files > guardScanFileLimit:
		s.exceeded = fmt.Errorf("the hook scan read more than %d files", guardScanFileLimit)
	case s.bytes > guardScanByteLimit:
		s.exceeded = fmt.Errorf("the hook scan read more than %d bytes", guardScanByteLimit)
	}
	return s.exceeded
}

func (s *guardScan) readFile(path string) ([]byte, bool, error) {
	return s.readFileLimit(path, guardFileLimit)
}

// readSource reads a file source, honoring its limit and inline content.
func (s *guardScan) readSource(source hookSource) ([]byte, bool, error) {
	if source.inline != nil {
		if len(source.inline) > guardFileLimit {
			return nil, true, guardLimit("%s exceeds %d bytes", source.path, guardFileLimit)
		}
		return source.inline, true, s.check()
	}
	limit := int64(guardFileLimit)
	if source.limit > 0 {
		limit = source.limit
	}
	return s.readFileLimit(source.path, limit)
}

func (s *guardScan) readFileLimit(path string, limit int64) ([]byte, bool, error) {
	if err := s.check(); err != nil {
		return nil, true, err
	}
	data, exists, err := readGuardFileLimit(path, limit)
	if exists {
		s.files++
		s.bytes += int64(len(data))
	}
	if err == nil {
		err = s.check()
	}
	return data, exists, err
}

func (s *guardScan) readDir(path string) ([]fs.DirEntry, bool, error) {
	if err := s.check(); err != nil {
		return nil, true, err
	}
	entries, exists, err := readGuardDir(path)
	if err == nil && len(entries) > guardDirEntryLimit {
		err = guardLimit("%s has more than %d entries", path, guardDirEntryLimit)
	}
	if err == nil {
		err = s.check()
	}
	return entries, exists, err
}

func (s *guardScan) scanPluginDir(source hookSource) []Finding {
	req := s.req
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
		path := filepath.Join(source.path, name)
		if strings.HasPrefix(name, ".") || req.ownedPluginPath(path) {
			continue
		}
		child := source.child(path, formatPluginDir)
		if entry.IsDir() {
			digest, err := s.treeDigest(path)
			if err != nil {
				findings = append(findings, s.unreadable(child, err))
			} else {
				findings = append(findings, findingFor(req, child, "", name, digest, "plugin directory"))
			}
		} else if data, _, err := s.readFile(path); err != nil {
			findings = append(findings, s.unreadable(child, err))
		} else {
			findings = append(findings, findingFor(req, child, "", name, sha256Hex(data), "plugin"))
		}
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

func (s *guardScan) scanPluginList(source hookSource, data []byte) []Finding {
	req := s.req
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	// Plugin paths in a config file resolve against its directory.
	entrySource := source
	entrySource.base = filepath.Dir(source.path)
	var findings []Finding
	for _, item := range list {
		name := ""
		switch v := item.(type) {
		case string:
			name = v
		case []any:
			if len(v) > 0 {
				name, _ = v[0].(string)
			}
		}
		if path, ok := pluginSpecPath(name, entrySource.base); ok && req.ownedPluginPath(path) {
			continue
		}
		files, problem := s.referencedFiles([]handlerValue{{text: name, exec: true}}, entrySource, nil)
		digest := sha256Hex(canonicalJSON(orderedFromMap(map[string]any{
			"plugin": item,
			"files":  files,
		})))
		finding := findingFor(req, source, "", name, digest, "plugin")
		finding.key = sha256Hex(canonicalJSON(item))
		if problem != "" {
			finding.Allowed = false
			finding.Reason = unapprovableReason + problem
		}
		findings = append(findings, finding)
	}
	return findings
}

// pluginSpecPath resolves a plugin-list entry that names a file (a file://
// URL, an absolute path, or a path relative to the config file). Package
// names are not files.
func pluginSpecPath(spec, base string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if rest, ok := strings.CutPrefix(spec, "file://"); ok {
		if decoded, err := url.PathUnescape(rest); err == nil {
			rest = decoded
		}
		if runtimeGOOS() == "windows" && len(rest) > 2 && rest[0] == '/' && rest[2] == ':' {
			rest = rest[1:]
		}
		return filepath.Clean(filepath.FromSlash(rest)), filepath.IsAbs(filepath.FromSlash(rest))
	}
	switch {
	case filepath.IsAbs(spec):
		return filepath.Clean(spec), true
	case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, `.\`) || strings.HasPrefix(spec, `..\`):
		if base == "" {
			return "", false
		}
		return filepath.Join(base, spec), true
	}
	return "", false
}

// decodeGuardDocument decodes a hook or plugin config. Several agents read
// JSONC (Devin, OpenCode), so comments and trailing commas are accepted;
// strict reports whether the bytes were plain JSON (the cleanup rewrites
// only those, so no comment is ever dropped).
func decodeGuardDocument(data []byte) (*object, bool, error) {
	doc, err := decodeOrderedObject(data)
	if err == nil {
		return doc, true, nil
	}
	relaxed, relaxedErr := decodeOrderedObject(stripJSONCTrailingCommas(stripJSONCComments(data)))
	if relaxedErr != nil {
		return nil, false, err
	}
	return relaxed, false, nil
}

// ScanForeignHooks returns every foreign hook or plugin for req.
func ScanForeignHooks(req GuardRequest) []Finding {
	return newGuardScan(req).scan(false)
}

// scan reads every source once. With stopAtBlocking it returns at the
// first unapproved finding.
func (s *guardScan) scan(stopAtBlocking bool) []Finding {
	req := s.req
	var findings []Finding
	blocking := func(list []Finding) bool {
		for _, finding := range list {
			if !finding.Allowed {
				return true
			}
		}
		return false
	}
	for _, source := range guardSources(req) {
		var found []Finding
		switch {
		case source.err != nil:
			found = []Finding{s.unreadable(source, source.err)}
		case source.format == formatFlatDir:
			found = s.scanFlatDir(source)
		case source.format == formatPluginDir:
			found = s.scanPluginDir(source)
		case source.format == formatClaudePlugins:
			found = s.scanClaudePlugins(source)
		case source.format == formatDevinPlugins:
			found = s.scanDevinPlugins(source)
		default:
			found = s.scanFile(source)
		}
		findings = append(findings, found...)
		if s.exceeded != nil || (stopAtBlocking && blocking(found)) {
			break
		}
	}
	return findings
}

func (s *guardScan) scanFlatDir(source hookSource) []Finding {
	entries, exists, err := s.readDir(source.path)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	if !exists {
		return nil
	}
	var findings []Finding
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		child := source.child(filepath.Join(source.path, entry.Name()), formatFlat)
		findings = append(findings, s.scanFile(child)...)
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

func (s *guardScan) scanFile(source hookSource) []Finding {
	data, exists, err := s.readSource(source)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	switch source.format {
	case formatCodexTOML:
		return s.scanCodexTOML(source, data)
	case formatPluginList:
		return s.scanPluginList(source, data)
	case formatHermesYAML:
		return s.scanHermesYAML(source, data)
	default:
		return s.scanJSONHooks(source, data)
	}
}

// EvaluateForeignHooks scans and decides. With foreign_hooks remove, any
// unapproved finding denies; report allows but returns the findings; allow
// (or a connector the guard does not cover) skips the scan.
func EvaluateForeignHooks(req GuardRequest) GuardDecision {
	if !req.Policy.Guard || req.Policy.ForeignHooks == config.ForeignHooksAllow {
		return GuardDecision{}
	}
	stopAtBlocking := req.StopAtFirstBlocking && req.Policy.ForeignHooks == config.ForeignHooksRemove
	scan := newGuardScan(req)
	decision := GuardDecision{Findings: scan.scan(stopAtBlocking)}
	decision.Incomplete = scan.exceeded != nil || scan.limited
	var blocking []Finding
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			blocking = append(blocking, finding)
		}
	}
	if len(blocking) == 0 || req.Policy.ForeignHooks != config.ForeignHooksRemove {
		return decision
	}
	first := blocking[0]
	what := "defines a hook"
	advice := foreignHookAdvice(req.Connector, first.Reason)
	switch {
	case first.Reason == "plugin" || first.Reason == "plugin directory":
		what = "adds a plugin"
	case strings.HasPrefix(first.Reason, "cannot verify"):
		what = "cannot be verified (" + strings.TrimPrefix(first.Reason, "cannot verify hook file: ") + ")"
	case strings.HasPrefix(first.Reason, unapprovableReason):
		what = "defines a hook"
		if first.Event == "" {
			what = "adds a plugin"
		}
		what += " that cannot be approved (" + strings.TrimPrefix(first.Reason, unapprovableReason) + ")"
	}
	decision.Deny = true
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. The %s file %s %s (digest sha256:%s)%s. %s",
		req.Connector, first.Scope, first.Path, what, first.Digest, moreFindings(len(blocking)-1, stopAtBlocking), advice,
	)
	return decision
}

// foreignHookAdvice tells the user how a blocked hook or plugin stops
// blocking: remove it or have it approved by digest, unless it is one no
// approval can cover.
func foreignHookAdvice(connector, reason string) string {
	if strings.HasPrefix(reason, unapprovableReason) {
		return "Remove it: an approval must cover every file the entry runs, so it can name only readable regular files and variables DefenseClaw can resolve."
	}
	return fmt.Sprintf("Remove it, or ask your administrator to add the digest to enterprise.machine_policy.connectors.%s.allowed_hooks.", connector)
}

func moreFindings(n int, stoppedEarly bool) string {
	if stoppedEarly {
		// The scan stopped at the first finding; others may exist.
		return ""
	}
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", n)
}
