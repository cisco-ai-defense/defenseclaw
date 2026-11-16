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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Claude Code merges managed-settings.json first, then every non-hidden
// *.json in managed-settings.d alphabetically; lists union, objects merge
// key by key and later scalars win. DefenseClaw owns exactly one drop-in.
// Claude Code selects the highest-ranked admin source (server-managed, MDM
// plist / HKLM, then the files as one source) that carries a policy key, a
// key other than managedSourcesBehavior and wslInheritsWindowsSettings, and
// ignores the rest unless managedSourcesBehavior is "merge" (Claude Code
// 2.1.242 and later). Env variables merge across admin sources from Claude
// Code 2.1.223; before that only the selected source's env applies.
const (
	claudeConnector              = ConnectorClaudeCode
	claudeMergeMinimumVersion    = "2.1.242"
	claudeEnvMergeMinimumVersion = "2.1.223"
)

type claudeTarget struct{}

func (claudeTarget) Name() string { return claudeConnector }

func claudeDropInPath(opts Options) (string, error) {
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		return "", err
	}
	return joinFor(opts, joinFor(opts, dir, "managed-settings.d"), DefenseClawDropInName), nil
}

func (claudeTarget) Paths(opts Options) ([]string, error) {
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		return nil, err
	}
	dropIn, err := claudeDropInPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{joinFor(opts, dir, "managed-settings.json"), dropIn}, nil
}

// claudeHandler renders DefenseClaw's hook handler for one group.
func claudeHandler(opts Options, group connector.ManagedHookGroup) *object {
	handler := newObject()
	handler.set("type", "command")
	// Claude starts the native binary directly on every platform. The
	// registered command does not inherit shell options from the agent.
	handler.set("command", opts.HookBinary)
	handler.set("args", []any{"hook", "--connector", "claudecode", "--enterprise-managed"})
	handler.set("timeout", json.Number(fmt.Sprint(group.Timeout)))
	if group.Async {
		handler.set("async", true)
	}
	return handler
}

// renderClaudeDropIn renders the complete DefenseClaw drop-in.
func renderClaudeDropIn(opts Options, policy config.ResolvedConnectorPolicy) ([]byte, error) {
	groups, err := connector.ManagedHookGroupsForOS(claudeConnector, opts.agentVersion(claudeConnector), opts.goos())
	if err != nil {
		return nil, err
	}
	doc := newObject()
	if policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce {
		doc.set("allowManagedHooksOnly", true)
	}
	if opts.goos() != "windows" {
		// This env value also governs Bash tool commands. Keep their shell
		// prefix at the managed default while the hook itself uses exec form.
		env := newObject()
		env.set("CLAUDE_CODE_SHELL_PREFIX", "")
		doc.set("env", env)
	}
	hooks := newObject()
	for _, group := range groups {
		entry := newObject()
		if group.Matcher != "" {
			entry.set("matcher", group.Matcher)
		}
		entry.set("hooks", []any{claudeHandler(opts, group)})
		existing, _ := hooks.get(group.Event)
		list, _ := existing.([]any)
		hooks.set(group.Event, append(list, entry))
	}
	doc.set("hooks", hooks)
	return encodeOrdered(doc)
}

// renderClaudeHigherPrecedence renders DefenseClaw's entries for a source
// that outranks the managed settings files (HKLM Settings, the managed
// preferences plist). Claude Code builds older than 2.1.242 read only that
// source, and every build the version floor is meant to stop is older, so
// under version_floor: enforce it also carries requiredMinimumVersion at the
// floor. The managed-settings.d hook drop-in (renderClaudeDropIn) never does:
// the floor has its own drop-in there.
func renderClaudeHigherPrecedence(opts Options, policy config.ResolvedConnectorPolicy) ([]byte, error) {
	rendered, err := renderClaudeDropIn(opts, policy)
	if err != nil || opts.claudeVersionFloorMode() != config.ClaudeVersionFloorEnforce {
		return rendered, err
	}
	floor := claudeVersionFloorFor(opts)
	if floor == "" {
		return rendered, nil
	}
	doc, err := decodeOrderedObject(rendered)
	if err != nil {
		return nil, err
	}
	doc.set(claudeVersionFloorKey, floor)
	return encodeOrdered(doc)
}

// claudeHandlerIsOwned reports whether a decoded handler uses the current
// managed form. Earlier forms need a policy refresh before they count.
func claudeHandlerIsOwned(opts Options, raw any) bool {
	command := stringField(raw, "command")
	if opts.goos() == "windows" {
		// Windows managed Setup registers the launcher through the guarded
		// cmd.exe form; that is the current managed form on that host.
		if fields := claudeHandlerFields(raw); fields != nil {
			if launcher, _, guarded := connector.ClaudeCodeManagedGuardLauncher(fields); guarded {
				return strings.EqualFold(launcher, opts.HookBinary)
			}
		}
		if !strings.EqualFold(command, opts.HookBinary) {
			return false
		}
	} else if command != opts.HookBinary {
		return false
	}
	var args []any
	switch v := raw.(type) {
	case *object:
		args, _ = v.values["args"].([]any)
	case map[string]any:
		args, _ = v["args"].([]any)
	}
	want := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	if len(args) != len(want) {
		return false
	}
	for i := range want {
		if s, _ := args[i].(string); s != want[i] {
			return false
		}
	}
	return true
}

// claudeHandlerIsLegacyOwned keeps earlier drop-ins recognizable for cleanup.
func claudeHandlerIsLegacyOwned(opts Options, raw any) bool {
	return opts.goos() != "windows" && stringField(raw, "command") == shellQuote(opts.HookBinary)+" hook --connector claudecode --enterprise-managed"
}

func claudeEventLists(hooks any) map[string][]any {
	eventLists := map[string][]any{}
	switch v := hooks.(type) {
	case *object:
		for _, key := range v.keys {
			list, _ := v.values[key].([]any)
			eventLists[key] = list
		}
	case map[string]any:
		for key, value := range v {
			list, _ := value.([]any)
			eventLists[key] = list
		}
	}
	return eventLists
}

// claudeEnvValue returns doc's env value for name.
func claudeEnvValue(doc *object, name string) (any, bool) {
	if doc == nil {
		return nil, false
	}
	raw, _ := doc.get("env")
	switch env := raw.(type) {
	case *object:
		return env.get(name)
	case map[string]any:
		value, ok := env[name]
		return value, ok
	}
	return nil, false
}

// inspectClaudeShellEnvironment reports managed env values that affect Bash
// tool scripts and returns the effective file-based prefix. The native
// DefenseClaw hook uses exec form.
func inspectClaudeShellEnvironment(opts Options, sources []claudeSource, state *State) (any, bool) {
	dropIn, _ := claudeDropInPath(opts)
	var prefix any
	var prefixSet bool
	for _, source := range sources {
		if value, ok := claudeEnvValue(source.doc, "CLAUDE_CODE_SHELL_PREFIX"); ok {
			prefix, prefixSet = value, true
			if text, isText := value.(string); isText {
				if source.name != dropIn && text != "" {
					state.detail("%s sets env CLAUDE_CODE_SHELL_PREFIX; verify the effective managed value is empty for Bash tool commands (rel-1-0-6:GAP-0322)", source.name)
				}
			}
		}
		inspectClaudeShellopts(source.name, source.doc, state)
	}
	return prefix, prefixSet
}

// inspectClaudeShellopts reports settings that reach Bash tool scripts. The
// native managed hook uses exec form and does not read shell options.
func inspectClaudeShellopts(name string, doc *object, state *State) {
	value, ok := claudeEnvValue(doc, "SHELLOPTS")
	if !ok {
		return
	}
	text, isText := value.(string)
	switch {
	case isText && strings.TrimSpace(text) == "":
		// An empty value is exported by bash, so the options of Claude
		// Code's shell snapshot reach every script.
		state.detail("%s sets env SHELLOPTS to \"\", which breaks Bash tool scripts: bash exports it, so the onecmd option of Claude Code's shell snapshot reaches every script the Bash tool starts and each runs its first command only; remove SHELLOPTS from that env block (rel-1-0-6:GAP-0465)", name)
	case isText && claudeShelloptsNoexec(text):
		state.detail("%s sets env SHELLOPTS with noexec; managed exec-form hooks are unaffected, but Bash tool scripts can inherit that option (rel-1-0-6:GAP-0322)", name)
	default:
		state.detail("%s sets env SHELLOPTS, which Claude Code passes to Bash tool commands; review shell startup options if scripts stop early (rel-1-0-6:GAP-0465)", name)
	}
}

func claudeShelloptsNoexec(value string) bool {
	for _, option := range strings.Split(value, ":") {
		if strings.TrimSpace(option) == "noexec" {
			return true
		}
	}
	return false
}

// countClaudeHooks counts DefenseClaw and foreign handlers in a settings
// "hooks" value and reports which contracted events lack DefenseClaw.
// A contracted event counts only when Claude Code runs a DefenseClaw handler
// for it: the entry matcher covers the contract and the handler is a
// blocking command (claudeEntryCovers, claudeHandlerRuns).
func countClaudeHooks(opts Options, hooks any, groups []connector.ManagedHookGroup) (owned, foreign int, missing []string) {
	eventLists := claudeEventLists(hooks)
	for _, list := range eventLists {
		for _, entry := range list {
			for _, handler := range handlersOf(entry) {
				if claudeHandlerIsOwned(opts, handler) {
					owned++
				} else if !claudeHandlerIsLegacyOwned(opts, handler) {
					foreign++
				}
			}
		}
	}
	for _, group := range groups {
		found := false
		for _, entry := range eventLists[group.Event] {
			if !claudeEntryCovers(entry, group) {
				continue
			}
			for _, handler := range handlersOf(entry) {
				if claudeHandlerIsOwned(opts, handler) && claudeHandlerRuns(handler, group) {
					found = true
				}
			}
		}
		if !found {
			missing = append(missing, group.Event)
		}
	}
	return owned, foreign, missing
}

// claudeEventsWithoutMatcher fire on every occurrence; Claude Code ignores
// a matcher on them.
var claudeEventsWithoutMatcher = map[string]bool{
	"UserPromptSubmit": true, "PostToolBatch": true, "Stop": true, "TeammateIdle": true,
	"TaskCreated": true, "TaskCompleted": true, "WorktreeCreate": true, "WorktreeRemove": true,
	"MessageDisplay": true, "CwdChanged": true,
}

// claudeEntryCovers reports whether an entry's matcher selects every
// occurrence the contract's matcher does: an omitted, "" or "*" matcher
// matches all. A restricted unanchored regex that matches the empty string
// also matches every tool name. Other expressions must equal the contract's
// matcher.
func claudeEntryCovers(entry any, group connector.ManagedHookGroup) bool {
	if claudeEventsWithoutMatcher[group.Event] {
		return true
	}
	var raw any
	var present bool
	switch v := entry.(type) {
	case *object:
		raw, present = v.get("matcher")
	case map[string]any:
		raw, present = v["matcher"]
	default:
		return false
	}
	if !present {
		return true
	}
	matcher, ok := raw.(string)
	return ok && (matcher == "" || matcher == "*" || matcher == group.Matcher || claudeMatcherMatchesAll(matcher))
}

// Keep this proof within regex syntax shared by Go and JavaScript. Claude
// Code treats names and separators alone as an exact-name list, not a regex.
// Without anchors or lookarounds, an empty regex match is available at every
// input start.
func claudeMatcherMatchesAll(matcher string) bool {
	if matcher == "^" || matcher == "$" {
		return true
	}
	regexPath := false
	for _, char := range matcher {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- ,|", char) {
			regexPath = true
			break
		}
	}
	if !regexPath {
		return false
	}
	if strings.Contains(strings.ReplaceAll(matcher, "(?:", ""), "(?") {
		return false
	}
	for i := 0; i < len(matcher); i++ {
		if matcher[i] == '[' {
			start := i
			i++
			if i < len(matcher) && matcher[i] == '^' {
				i++
			}
			for ; i < len(matcher) && matcher[i] != ']'; i++ {
				if matcher[i] == '\\' {
					i++
					if i == len(matcher) || !strings.ContainsRune("sSdDwW", rune(matcher[i])) {
						return false
					}
				} else if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- .", rune(matcher[i])) {
					return false
				}
			}
			if i == len(matcher) || i == start+1 || (i == start+2 && matcher[start+1] == '^') {
				return false
			}
			continue
		}
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- ,._*+?|():", rune(matcher[i])) {
			return false
		}
	}
	compiled, err := regexp.Compile(matcher)
	return err == nil && compiled.MatchString("")
}

// claudeHandlerFields is the field map of a decoded handler, or nil.
func claudeHandlerFields(raw any) map[string]any {
	switch v := raw.(type) {
	case *object:
		return v.values
	case map[string]any:
		return v
	}
	return nil
}

// claudeHandlerRuns reports whether Claude Code runs a handler as a command
// that can decide the call: type "command", no "if" filter, and no
// background run unless the contract runs the group in the background.
func claudeHandlerRuns(raw any, group connector.ManagedHookGroup) bool {
	fields := claudeHandlerFields(raw)
	if fields == nil {
		return false
	}
	if fields["type"] != "command" {
		return false
	}
	if _, filtered := fields["if"]; filtered {
		return false
	}
	if !group.Async {
		for _, key := range []string{"async", "asyncRewake"} {
			if value, set := fields[key]; set && value != false {
				return false
			}
		}
	}
	return true
}

// claudeHasPolicyKey reports whether doc carries a non-null policy value.
// Claude Code skips a source with only control keys or null policy values.
func claudeHasPolicyKey(doc *object) bool {
	for _, key := range doc.keys {
		if key != "managedSourcesBehavior" && key != "wslInheritsWindowsSettings" {
			if value, present := doc.get(key); present && value != nil {
				return true
			}
		}
	}
	return false
}

// claudeShellPrefixConflict returns a conflict unless the
// CLAUDE_CODE_SHELL_PREFIX value Claude Code applies to Bash tool commands
// is "". From Claude Code 2.1.223 each env variable comes from the
// highest-ranked admin source that sets it; before that, only from the
// selected source (the highest-ranked one with a policy key). The file
// sources count as one source whose last value wins. An unknown client
// version must pass under both rules.
func claudeShellPrefixConflict(opts Options, higher []higherClaudeSource, filePrefix any, filePrefixSet bool) string {
	rules := []bool{true, false}
	if version := opts.agentVersion(claudeConnector); version != "" {
		rules = []bool{compareVersions(version, claudeEnvMergeMinimumVersion) >= 0}
	}
	for _, perVariable := range rules {
		value, set, from := filePrefix, filePrefixSet, ""
		for _, source := range higher {
			if perVariable {
				if v, ok := claudeEnvValue(source.doc, "CLAUDE_CODE_SHELL_PREFIX"); ok {
					value, set, from = v, true, source.name
					break
				}
			} else if claudeHasPolicyKey(source.doc) {
				value, set = claudeEnvValue(source.doc, "CLAUDE_CODE_SHELL_PREFIX")
				from = source.name
				break
			}
		}
		if text, isText := value.(string); set && isText && text == "" {
			continue
		}
		if from == "" {
			return "managed Claude Code settings do not keep CLAUDE_CODE_SHELL_PREFIX empty for Bash tool commands (rel-1-0-6:GAP-0322)"
		}
		return fmt.Sprintf("effective managed policy from %s does not keep CLAUDE_CODE_SHELL_PREFIX empty for Bash tool commands (rel-1-0-6:GAP-0322)", from)
	}
	return ""
}

func handlersOf(entry any) []any {
	switch v := entry.(type) {
	case *object:
		list, _ := v.values["hooks"].([]any)
		return list
	case map[string]any:
		list, _ := v["hooks"].([]any)
		return list
	}
	return nil
}

// claudeSource is one managed settings document in merge order.
type claudeSource struct {
	name string
	doc  *object
}

func readClaudeFileSources(opts Options) ([]claudeSource, error) {
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		return nil, err
	}
	var sources []claudeSource
	base := joinFor(opts, dir, "managed-settings.json")
	if data, exists, err := readPolicyFile(opts, base); err != nil {
		return nil, err
	} else if exists {
		doc, err := decodeOrderedObject(bytes.TrimPrefix(data, utf8BOM))
		if err != nil {
			return nil, fmt.Errorf("%s: %w; DefenseClaw cannot check Claude Code's managed settings until this file parses as JSON: fix it, then rerun", base, err)
		}
		sources = append(sources, claudeSource{name: base, doc: doc})
	}
	dropDir := platformPath(opts, joinFor(opts, dir, "managed-settings.d"))
	entries, err := os.ReadDir(dropDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	names := []string{}
	for _, entry := range entries {
		if effectivePolicyDropIn(entry) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		file := joinFor(opts, joinFor(opts, dir, "managed-settings.d"), name)
		data, exists, err := readPolicyFile(opts, file)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		doc, err := decodeOrderedObject(bytes.TrimPrefix(data, utf8BOM))
		if err != nil {
			return nil, fmt.Errorf("%s: %w; DefenseClaw cannot check Claude Code's managed settings until this drop-in parses as JSON: fix it, then rerun", file, err)
		}
		sources = append(sources, claudeSource{name: file, doc: doc})
	}
	return sources, nil
}

// utf8BOM starts a file a Windows editor saved as "UTF-8 with BOM". Claude
// Code and Codex read such a managed file (and its CRLF line ends), so
// DefenseClaw does too: it refused one, failed verify for every user and
// claimed Claude Code would not start (GAP-0914, GAP-0917).
var utf8BOM = []byte("\xef\xbb\xbf")

// claudeEffectiveScalar returns the last file-based value for key.
func claudeEffectiveScalar(sources []claudeSource, key string) (any, string) {
	var value any
	var from string
	for _, source := range sources {
		if v, ok := source.doc.get(key); ok {
			value, from = v, source.name
		}
	}
	return value, from
}

// higherClaudeSource is a higher-precedence admin source (HKLM Settings,
// the macOS managed-preferences plist) decoded to JSON.
type higherClaudeSource struct {
	name string
	doc  *object
}

// claudeHigherSources is replaced per platform.
var claudeHigherSources = platformClaudeHigherSources

func inspectClaude(opts Options, policy config.ResolvedConnectorPolicy, state *State) error {
	sources, err := readClaudeFileSources(opts)
	if err != nil {
		return err
	}
	groups, err := connector.ManagedHookGroupsForOS(claudeConnector, opts.agentVersion(claudeConnector), opts.goos())
	if err != nil {
		return err
	}
	events := make([]string, 0, len(groups))
	for _, group := range groups {
		events = append(events, group.Event)
	}
	// Lists union across files, so count across every file-based source.
	missingAll := map[string]bool{}
	for _, event := range events {
		missingAll[event] = true
	}
	for _, source := range sources {
		hooks, _ := source.doc.get("hooks")
		owned, foreign, missing := countClaudeHooks(opts, hooks, groups)
		state.OwnedEntries += owned
		state.ForeignEntries += foreign
		missingSet := map[string]bool{}
		for _, event := range missing {
			missingSet[event] = true
		}
		for _, event := range events {
			if !missingSet[event] {
				delete(missingAll, event)
			}
		}
	}
	for _, event := range events {
		if missingAll[event] {
			state.entryConflict("Claude Code event %s has no DefenseClaw managed hook that runs for it (a command handler with DefenseClaw's command and args, a matcher covering the contract, no if filter, not async)", event)
		}
	}
	if value, from := claudeEffectiveScalar(sources, "disableAllHooks"); value == true {
		state.conflict("%s sets disableAllHooks: true in managed settings, which disables DefenseClaw's managed hooks", from)
	}
	lockValue, lockFrom := claudeEffectiveScalar(sources, "allowManagedHooksOnly")
	if lockValue == true {
		state.EffectiveLock = config.ManagedHooksOnlyEnforce
	} else {
		state.EffectiveLock = config.ManagedHooksOnlyPreserve
	}
	if policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce && lockValue != true {
		if lockFrom != "" {
			state.conflict("%s sets allowManagedHooksOnly to %v after DefenseClaw's drop-in; user and project hooks can rewrite tool input after inspection", lockFrom, lockValue)
		} else {
			state.conflict("allowManagedHooksOnly is not true in managed settings; user and project hooks can rewrite tool input after inspection")
		}
	}
	if policy.ManagedHooksOnly == config.ManagedHooksOnlyPreserve && lockValue != true {
		state.detail("managed_hooks_only: preserve — user and project Claude Code hooks still run and can rewrite tool input (updatedInput) after DefenseClaw approves it")
	}
	var filePrefix any
	var filePrefixSet bool
	if opts.goos() != "windows" {
		filePrefix, filePrefixSet = inspectClaudeShellEnvironment(opts, sources, state)
	}
	if value, from := claudeEffectiveScalar(sources, "policyHelper"); value != nil {
		state.conflict("%s configures policyHelper, which lets an external helper decide managed policy; DefenseClaw cannot verify the effective hooks", from)
	}

	higher, err := claudeHigherSources(opts)
	if err != nil {
		state.conflict("inspect higher-precedence Claude Code policy: %v", err)
	}
	if opts.goos() != "windows" {
		// Checked whichever source is selected: env merges across sources.
		if message := claudeShellPrefixConflict(opts, higher, filePrefix, filePrefixSet); message != "" {
			state.conflict("%s", message)
		}
	}
	for _, source := range higher {
		if opts.goos() != "windows" {
			inspectClaudeShellopts(source.name, source.doc, state)
		}
		hooks, _ := source.doc.get("hooks")
		_, _, missing := countClaudeHooks(opts, hooks, groups)
		behavior, _ := source.doc.get("managedSourcesBehavior")
		if value, _ := source.doc.get("policyHelper"); value != nil {
			state.conflict("%s configures policyHelper, which lets an external helper decide managed policy; DefenseClaw cannot verify the effective hooks", source.name)
		}
		switch {
		case len(missing) == 0:
			state.detail("%s embeds DefenseClaw's hook matrix", source.name)
		case behavior == "merge":
			state.detail("%s sets managedSourcesBehavior: merge, so Claude Code %s and later also apply DefenseClaw's drop-in", source.name, claudeMergeMinimumVersion)
			if version := opts.agentVersion(claudeConnector); version != "" && compareVersions(version, claudeMergeMinimumVersion) < 0 {
				state.Pending = append(state.Pending, fmt.Sprintf("Claude Code %s is older than %s and ignores managedSourcesBehavior: merge", version, claudeMergeMinimumVersion))
			}
		case !claudeHasPolicyKey(source.doc):
			// Claude Code skips it and selects the next source.
			state.detail("%s carries only managed-source control keys, so Claude Code applies the next managed source", source.name)
		default:
			state.HigherPrecedence = append(state.HigherPrecedence, source.name)
			// A macOS managed-preferences profile takes the plist export.
			format := "claude-hklm-json"
			if opts.goos() == "darwin" {
				format = "plist"
			}
			message := fmt.Sprintf("%s has higher precedence than file-based managed settings and does not include DefenseClaw's hooks for %s; add \"managedSourcesBehavior\": \"merge\" to it (Claude Code %s+) or deploy %s through it (the export also sets requiredMinimumVersion under version_floor: enforce)", source.name, strings.Join(missing, ", "), claudeMergeMinimumVersion,
				policyExportCommand(opts.goos(), "--connector", "claudecode", "--format", format))
			if policy.HigherPrecedenceSources == config.HigherPrecedenceWarn {
				state.detail("%s", message)
				state.HigherPrecedence = state.HigherPrecedence[:len(state.HigherPrecedence)-1]
			} else {
				state.conflict("%s", message)
			}
		}
	}
	if err := inspectClaudeVersionFloor(opts, policy, sources, higher, state); err != nil {
		state.conflict("Claude Code version floor: %v", err)
	}
	state.detail("server-managed settings from the claude.ai console are not visible locally; %s", liveProofNote(opts, claudeConnector, "Claude Code", "hooks"))
	state.detail("residual: `claude --bare` and CLAUDE_CODE_SIMPLE=1 skip the managed SessionStart hook (Claude Code 2.1.287 still runs UserPromptSubmit, PreToolUse and later tool hooks; other releases may skip UserPromptSubmit too); Claude Code offers no managed control for this")
	return nil
}

func newClaudeState(policy config.ResolvedConnectorPolicy, paths []string) State {
	return State{
		Connector:    claudeConnector,
		Route:        RouteMachinePolicy,
		Ownership:    policy.Ownership,
		Lock:         policy.ManagedHooksOnly,
		ForeignHooks: policy.ForeignHooks,
		Paths:        paths,
	}
}

func (t claudeTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(claudeConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newClaudeState(policy, paths)
	switch policy.Ownership {
	case config.MachinePolicyOwnershipOff:
		state.Route = RouteUnsupported
		return state, nil
	case config.MachinePolicyOwnershipMerge:
		path, _ := claudeDropInPath(opts)
		rendered, err := renderClaudeDropIn(opts, policy)
		if err != nil {
			return state, err
		}
		current, exists, err := readPolicyFile(opts, path)
		if err != nil {
			return state, err
		}
		if exists && !bytes.Equal(current, rendered) {
			if _, err := decodeOrderedObject(current); err != nil {
				state.detail("replacing unparsable %s", path)
			}
		}
		changed, err := publishWithRecord(opts, claudeConnector, path, current, exists, rendered, exists && bytes.Equal(current, rendered), claudeStrip(opts), &state)
		if err != nil {
			return state, err
		}
		state.Changed = changed
		// The version floor is a separate drop-in: a failure to place it is
		// reported, and never keeps the hooks from counting as published.
		if err := applyClaudeVersionFloor(opts, policy, &state); err != nil {
			state.conflict("Claude Code version floor: %v", err)
		}
	}
	if err := inspectClaude(opts, policy, &state); err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly && state.OwnedEntries == 0 {
		state.detail("missing_defenseclaw_hooks: deploy the output of %s through your policy tool", policyExportCommand(opts.goos(), "--connector", "claudecode"))
	}
	state.finish()
	return state, nil
}

func (t claudeTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(claudeConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newClaudeState(policy, paths)
	if policy.Ownership == config.MachinePolicyOwnershipOff && opts.goos() != "windows" {
		state.Route = RouteUnsupported
		return state, nil
	}
	if opts.goos() == "windows" {
		path, err := claudeDropInPath(opts)
		if err != nil {
			return state, err
		}
		_, exists, err := readPolicyFile(opts, path)
		if err != nil {
			return state, err
		}
		if !exists {
			state.conflict("%s does not exist: %s", path, windowsMissingMachineHookDiagnostic("Claude Code"))
		}
		verifyWindowsHookExecutable(opts, "Claude Code", &state)
	}
	if err := inspectClaude(opts, policy, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t claudeTarget) RemoveOwned(opts Options) (State, error) {
	path, err := claudeDropInPath(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: claudeConnector, Route: RouteMachinePolicy, Paths: []string{path}}
	// The version floor goes first: the hook drop-in's record holds the
	// directories DefenseClaw created, which are empty only once both files
	// are gone.
	floorErr := removeClaudeVersionFloor(opts, &state)
	err = restoreOrStrip(opts, claudeConnector, path, claudeStrip(opts), true, &state)
	return state, errors.Join(floorErr, err)
}

// claudeStrip treats a drop-in carrying DefenseClaw hooks as a whole file
// DefenseClaw owns; any other content under the drop-in name is left alone.
// It only decides a file DefenseClaw has no record of publishing: once the
// ownership record names the drop-in, the file is DefenseClaw's whatever it
// holds (reservedDropIn), so an edited hook command is never taken for an
// administrator's content (GAP-1099).
func claudeStrip(opts Options) stripFunc {
	return wholeFileStrip(func(current []byte) bool {
		doc, err := decodeOrderedObject(current)
		if err != nil {
			return false
		}
		hooks, _ := doc.get("hooks")
		owned, _, _ := countClaudeHooks(opts, hooks, nil)
		if owned > 0 {
			return true
		}
		for _, list := range claudeEventLists(hooks) {
			for _, entry := range list {
				for _, handler := range handlersOf(entry) {
					if claudeHandlerIsLegacyOwned(opts, handler) {
						return true
					}
				}
			}
		}
		return false
	})
}

func (claudeTarget) Export(opts Options, format string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if format == "version-floor" {
		return exportClaudeVersionFloor(opts)
	}
	policy := opts.PolicyFor(claudeConnector)
	if format == "" || format == "json" {
		return renderClaudeDropIn(opts, policy)
	}
	rendered, err := renderClaudeHigherPrecedence(opts, policy)
	if err != nil {
		return nil, err
	}
	switch format {
	case "claude-hklm-json":
		var compact bytes.Buffer
		if err := json.Compact(&compact, rendered); err != nil {
			return nil, err
		}
		return append(compact.Bytes(), '\n'), nil
	case "reg":
		var compact bytes.Buffer
		if err := json.Compact(&compact, rendered); err != nil {
			return nil, err
		}
		escaped := strings.ReplaceAll(strings.ReplaceAll(compact.String(), `\`, `\\`), `"`, `\"`)
		return []byte("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\ClaudeCode]\r\n\"Settings\"=\"" + escaped + "\"\r\n"), nil
	case "plist":
		return renderPlist(rendered)
	case "intune-settings-catalog":
		var compact bytes.Buffer
		if err := json.Compact(&compact, rendered); err != nil {
			return nil, err
		}
		doc := map[string]any{
			"platform":    "windows",
			"description": "Deploy with an Intune Remediation or Win32 app script as SYSTEM; Claude Code reads this value as its HKLM managed policy. Merge it with any Settings value you already deploy (lists combine; set managedSourcesBehavior to merge to also apply file-based drop-ins).",
			"registry": map[string]any{
				"hive":  "HKEY_LOCAL_MACHINE",
				"key":   `SOFTWARE\Policies\ClaudeCode`,
				"name":  "Settings",
				"type":  "REG_SZ",
				"value": compact.String(),
			},
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(out, '\n'), nil
	default:
		return nil, fmt.Errorf("claudecode policy export supports json, claude-hklm-json, reg, plist, intune-settings-catalog and version-floor, not %q", format)
	}
}

// compareVersions compares dotted numeric versions (non-numeric suffixes
// ignored). It returns -1, 0 or 1.
func compareVersions(left, right string) int {
	parse := func(value string) []int {
		value = strings.TrimSpace(value)
		for i, r := range value {
			if r >= '0' && r <= '9' {
				value = value[i:]
				break
			}
		}
		var out []int
		for _, part := range strings.Split(value, ".") {
			n := 0
			digits := false
			for _, r := range part {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
				digits = true
			}
			if !digits {
				break
			}
			out = append(out, n)
		}
		return out
	}
	a, b := parse(left), parse(right)
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
