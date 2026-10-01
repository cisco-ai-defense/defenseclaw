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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Claude Code merges managed-settings.json first, then every non-hidden
// *.json in managed-settings.d alphabetically; lists union, objects merge
// key by key and later scalars win. DefenseClaw owns exactly one drop-in.
// Higher-ranked admin sources (server-managed, MDM plist / HKLM) are used
// instead of the files unless the highest source sets
// managedSourcesBehavior: "merge" (Claude Code 2.1.242 and later).
const (
	claudeConnector           = ConnectorClaudeCode
	claudeMergeMinimumVersion = "2.1.242"
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
	if opts.goos() == "windows" {
		// Claude's exec form starts the native launcher directly, with no
		// shell parsing of a path that may contain spaces (the Secure Client
		// profile certifies the same form).
		handler.set("command", opts.HookBinary)
		handler.set("args", []any{"hook", "--connector", "claudecode", "--enterprise-managed"})
	} else {
		handler.set("command", shellQuote(opts.HookBinary)+" hook --connector claudecode --enterprise-managed")
	}
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
	floor := ClaudeVersionFloor()
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

// claudeHandlerIsOwned reports whether a decoded handler is DefenseClaw's.
func claudeHandlerIsOwned(opts Options, raw any) bool {
	command := stringField(raw, "command")
	if opts.goos() == "windows" {
		if !strings.EqualFold(command, opts.HookBinary) {
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
	return command == shellQuote(opts.HookBinary)+" hook --connector claudecode --enterprise-managed"
}

// countClaudeHooks counts DefenseClaw and foreign handlers in a settings
// "hooks" value and reports which contracted events lack DefenseClaw.
func countClaudeHooks(opts Options, hooks any, events []string) (owned, foreign int, missing []string) {
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
	for _, list := range eventLists {
		for _, entry := range list {
			for _, handler := range handlersOf(entry) {
				if claudeHandlerIsOwned(opts, handler) {
					owned++
				} else {
					foreign++
				}
			}
		}
	}
	for _, event := range events {
		found := false
		for _, entry := range eventLists[event] {
			for _, handler := range handlersOf(entry) {
				if claudeHandlerIsOwned(opts, handler) {
					found = true
				}
			}
		}
		if !found {
			missing = append(missing, event)
		}
	}
	return owned, foreign, missing
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
		doc, err := decodeOrderedObject(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (Claude Code refuses to start with an unparsable managed settings file)", base, err)
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
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".json") || entry.IsDir() {
			continue
		}
		names = append(names, name)
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
		doc, err := decodeOrderedObject(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (Claude Code refuses to start with an unparsable managed drop-in)", file, err)
		}
		sources = append(sources, claudeSource{name: file, doc: doc})
	}
	return sources, nil
}

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
		owned, foreign, missing := countClaudeHooks(opts, hooks, events)
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
			state.conflict("Claude Code event %s has no DefenseClaw managed hook", event)
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
	if value, from := claudeEffectiveScalar(sources, "policyHelper"); value != nil {
		state.conflict("%s configures policyHelper, which lets an external helper decide managed policy; DefenseClaw cannot verify the effective hooks", from)
	}

	higher, err := claudeHigherSources(opts)
	if err != nil {
		state.conflict("inspect higher-precedence Claude Code policy: %v", err)
	}
	for _, source := range higher {
		hooks, _ := source.doc.get("hooks")
		_, _, missing := countClaudeHooks(opts, hooks, events)
		behavior, _ := source.doc.get("managedSourcesBehavior")
		switch {
		case len(missing) == 0:
			state.detail("%s embeds DefenseClaw's hook matrix", source.name)
		case behavior == "merge":
			state.detail("%s sets managedSourcesBehavior: merge, so Claude Code %s and later also apply DefenseClaw's drop-in", source.name, claudeMergeMinimumVersion)
			if version := opts.agentVersion(claudeConnector); version != "" && compareVersions(version, claudeMergeMinimumVersion) < 0 {
				state.Pending = append(state.Pending, fmt.Sprintf("Claude Code %s is older than %s and ignores managedSourcesBehavior: merge", version, claudeMergeMinimumVersion))
			}
		default:
			state.HigherPrecedence = append(state.HigherPrecedence, source.name)
			message := fmt.Sprintf("%s has higher precedence than file-based managed settings and does not include DefenseClaw's hooks; add \"managedSourcesBehavior\": \"merge\" to it (Claude Code %s+) or deploy `defenseclaw-gateway enterprise policy export --connector claudecode --format claude-hklm-json` through it (the export also sets requiredMinimumVersion under version_floor: enforce)", source.name, claudeMergeMinimumVersion)
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
	state.detail("server-managed settings from the claude.ai console are not visible locally; `enterprise policy verify --live --connector claudecode --user <user>` proves the effective hooks")
	state.detail("residual: `claude --bare` and CLAUDE_CODE_SIMPLE=1 skip managed SessionStart and UserPromptSubmit hooks (PreToolUse and later tool hooks still run); Claude Code offers no managed control for this")
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
		state.detail("missing_defenseclaw_hooks: deploy the output of `defenseclaw-gateway enterprise policy export --connector claudecode` through your policy tool")
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
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
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

// claudeStrip treats a drop-in carrying DefenseClaw's hooks as DefenseClaw's
// whole file; any other content under the drop-in name is left alone.
func claudeStrip(opts Options) stripFunc {
	return wholeFileStrip(func(current []byte) bool {
		doc, err := decodeOrderedObject(current)
		if err != nil {
			return false
		}
		hooks, _ := doc.get("hooks")
		owned, _, _ := countClaudeHooks(opts, hooks, nil)
		return owned > 0
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
