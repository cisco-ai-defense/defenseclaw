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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Codex requirements.toml is a single administrator file. DefenseClaw never
// re-marshals it: it owns two marked regions (top-level keys first, tables
// last) plus individually marked lines inside administrator tables, so
// comments, ordering and every administrator setting survive byte for byte.
const (
	codexHeadBegin  = "# >>> DefenseClaw managed settings (edits inside this block are replaced) >>>"
	codexHeadEnd    = "# <<< DefenseClaw managed settings <<<"
	codexTailBegin  = "# >>> DefenseClaw managed hooks (edits inside this block are replaced) >>>"
	codexTailEnd    = "# <<< DefenseClaw managed hooks <<<"
	codexOwnedMark  = "# defenseclaw-managed"
	codexConnector  = ConnectorCodex
	codexHooksTable = "hooks"
)

type codexTarget struct{}

func (codexTarget) Name() string { return codexConnector }

func (codexTarget) Paths(opts Options) ([]string, error) {
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}

// codexHookCommandForEvent is the command Codex runs for one managed event.
// The hook binds each Codex invocation to its installer-declared event and
// hook contract and fails closed without them, so every event group names
// both (live on RHEL an event-less command blocked every Codex prompt). On
// Windows it is the standalone requirements writer's command, which also
// waits for the GUI-subsystem launcher so its decision reaches Codex.
func codexHookCommandForEvent(opts Options, event string) string {
	contract := codexMachinePolicyContract(opts)
	if opts.goos() == "windows" {
		return connector.WindowsCodexStandaloneManagedHookCommand(opts.HookBinary, event, contract)
	}
	return shellQuote(opts.HookBinary) + " hook --connector codex --enterprise-managed --event " + event + " --hook-contract " + contract
}

// codexMachinePolicyContract is the hook contract the machine-wide Codex
// commands declare: the contract of the discovered machine Codex version,
// else the default contract for an unversioned agent.
func codexMachinePolicyContract(opts Options) string {
	if resolution := connector.ResolveHookContract(codexConnector, opts.agentVersion(codexConnector)); resolution.Contract.ContractID != "" {
		return resolution.Contract.ContractID
	}
	return connector.ResolveHookContract(codexConnector, "").Contract.ContractID
}

// codexOwnedCommands is every managed Codex command of groups.
func codexOwnedCommands(opts Options, groups []connector.ManagedHookGroup) map[string]bool {
	out := map[string]bool{}
	for _, group := range groups {
		out[codexHookCommandForEvent(opts, group.Event)] = true
	}
	return out
}

func codexManagedDirKey(opts Options) string {
	if opts.goos() == "windows" {
		return "windows_managed_dir"
	}
	return "managed_dir"
}

// shellQuote single-quotes a POSIX word.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// tomlString renders a TOML basic string.
func tomlString(value string) string {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.TrimSpace(buf.String())
}

var (
	tomlTableHeader = regexp.MustCompile(`^\s*\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$`)
	tomlArrayHeader = regexp.MustCompile(`^\s*\[\[\s*([^\[\]]+?)\s*\]\]\s*(#.*)?$`)
)

// stripCodexOwned removes DefenseClaw's regions and marked lines, leaving
// exactly the administrator's text.
func stripCodexOwned(raw []byte) []byte {
	lines := strings.SplitAfter(string(raw), "\n")
	var out strings.Builder
	skipping := ""
	skipBlank := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if skipBlank {
			skipBlank = false
			if trimmed == "" {
				continue
			}
		}
		switch {
		case skipping != "":
			if trimmed == skipping {
				// DefenseClaw separates its head block from administrator
				// content with one blank line; drop it with the block.
				skipBlank = skipping == codexHeadEnd
				skipping = ""
			}
			continue
		case trimmed == codexHeadBegin:
			skipping = codexHeadEnd
			continue
		case trimmed == codexTailBegin:
			skipping = codexTailEnd
			continue
		case strings.HasSuffix(trimmed, codexOwnedMark):
			continue
		}
		out.WriteString(line)
	}
	text := out.String()
	// Drop the separator newline DefenseClaw added before its tail block.
	return []byte(strings.TrimRight(text, "\n") + trailingNewline(text))
}

// codexHasOwned reports whether raw carries a DefenseClaw region or marked
// line.
func codexHasOwned(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == codexHeadBegin || trimmed == codexTailBegin || strings.HasSuffix(trimmed, codexOwnedMark) {
			return true
		}
	}
	return false
}

// codexStrip is the ownership stripFunc for requirements.toml: an
// administrator file without DefenseClaw content is returned untouched.
func codexStrip(current []byte) ([]byte, bool, error) {
	if !codexHasOwned(current) {
		return current, false, nil
	}
	return stripCodexOwned(current), true, nil
}

func trailingNewline(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return "\n"
}

// codexAdminLayout describes where administrator tables live.
type codexAdminLayout struct {
	firstTableLine int
	featuresHeader int // line index of "[features]", -1 when absent
	hooksHeader    int // line index of "[hooks]", -1 when absent
	inlineFeatures bool
	inlineHooks    bool
}

func analyzeCodexAdmin(lines []string) codexAdminLayout {
	layout := codexAdminLayout{firstTableLine: -1, featuresHeader: -1, hooksHeader: -1}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if match := tomlArrayHeader.FindStringSubmatch(line); match != nil {
			if layout.firstTableLine < 0 {
				layout.firstTableLine = i
			}
			continue
		}
		if match := tomlTableHeader.FindStringSubmatch(line); match != nil {
			if layout.firstTableLine < 0 {
				layout.firstTableLine = i
			}
			switch strings.Trim(strings.TrimSpace(match[1]), `"`) {
			case "features":
				layout.featuresHeader = i
			case codexHooksTable:
				layout.hooksHeader = i
			}
			continue
		}
		if layout.firstTableLine < 0 && strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "#") {
			key := strings.Trim(strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0]), `"`)
			if key == "features" || strings.HasPrefix(key, "features.") {
				layout.inlineFeatures = true
			}
			if key == codexHooksTable || strings.HasPrefix(key, codexHooksTable+".") {
				layout.inlineHooks = true
			}
		}
	}
	return layout
}

// renderCodex builds the merged requirements document from the
// administrator text. It returns the document and the conflicts that
// prevent DefenseClaw from claiming coverage.
func renderCodex(opts Options, admin []byte, policy config.ResolvedConnectorPolicy) ([]byte, []string, error) {
	adminCfg := map[string]any{}
	if len(bytes.TrimSpace(admin)) > 0 {
		if err := toml.Unmarshal(admin, &adminCfg); err != nil {
			return nil, nil, fmt.Errorf("parse administrator Codex requirements: %w", err)
		}
	}
	var conflicts []string
	lines := strings.SplitAfter(string(admin), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	layout := analyzeCodexAdmin(lines)
	if layout.inlineFeatures || layout.inlineHooks {
		return nil, []string{"requirements.toml defines features or hooks with top-level dotted keys or inline tables; DefenseClaw cannot merge into that layout without rewriting administrator content (use ownership: verify_only and deploy `policy export` output)"}, nil
	}

	var head []string
	if value, present := adminCfg["allow_managed_hooks_only"]; present {
		flag, ok := value.(bool)
		switch {
		case !ok:
			conflicts = append(conflicts, fmt.Sprintf("allow_managed_hooks_only has unsupported type %T", value))
		case !flag && policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce:
			conflicts = append(conflicts, "administrator requirements set allow_managed_hooks_only = false while enterprise.machine_policy requires enforce; DefenseClaw does not rewrite administrator values")
		}
	} else if policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce {
		head = append(head, "allow_managed_hooks_only = true")
	}

	insertAfter := map[int][]string{}
	var tail []string
	features, _ := adminCfg["features"].(map[string]any)
	if raw, present := features["hooks"]; present {
		if enabled, ok := raw.(bool); !ok || !enabled {
			conflicts = append(conflicts, "administrator requirements set features.hooks to a non-true value, which disables every managed hook")
		}
	} else if layout.featuresHeader >= 0 {
		insertAfter[layout.featuresHeader] = append(insertAfter[layout.featuresHeader], "hooks = true "+codexOwnedMark)
	} else {
		tail = append(tail, "[features]", "hooks = true", "")
	}

	hooksCfg, _ := adminCfg[codexHooksTable].(map[string]any)
	if _, present := hooksCfg["state"]; present {
		conflicts = append(conflicts, "hooks.state in machine requirements can change which managed hooks run; remove it")
	}
	managedDirKey := codexManagedDirKey(opts)
	managedDir := hookBinaryDir(opts)
	if raw, present := hooksCfg[managedDirKey]; present {
		if value, ok := raw.(string); !ok || !sameCodexPath(opts, value, managedDir) {
			conflicts = append(conflicts, fmt.Sprintf("hooks.%s=%v conflicts with DefenseClaw's hook directory %q", managedDirKey, raw, managedDir))
		}
	} else if layout.hooksHeader >= 0 {
		insertAfter[layout.hooksHeader] = append(insertAfter[layout.hooksHeader], managedDirKey+" = "+tomlString(managedDir)+" "+codexOwnedMark)
	} else {
		tail = append(tail, "[hooks]", managedDirKey+" = "+tomlString(managedDir), "")
	}

	groups, err := connector.ManagedHookGroupsForOS(codexConnector, opts.agentVersion(codexConnector), opts.goos())
	if err != nil {
		return nil, nil, err
	}
	for _, group := range groups {
		command := codexHookCommandForEvent(opts, group.Event)
		if countCodexOwnedGroups(hooksCfg[group.Event], group, command, opts) > 0 {
			continue
		}
		tail = append(tail, "[[hooks."+group.Event+"]]")
		if group.Matcher != "" {
			tail = append(tail, "matcher = "+tomlString(group.Matcher))
		}
		tail = append(tail, "", "[[hooks."+group.Event+".hooks]]", `type = "command"`, "command = "+tomlString(command))
		if opts.goos() == "windows" {
			tail = append(tail, "command_windows = "+tomlString(command))
		}
		tail = append(tail, "timeout = "+strconv.Itoa(group.Timeout), "")
	}

	var out strings.Builder
	if len(head) > 0 {
		out.WriteString(codexHeadBegin + "\n")
		for _, line := range head {
			out.WriteString(line + "\n")
		}
		out.WriteString(codexHeadEnd + "\n")
		if len(lines) > 0 {
			out.WriteString("\n")
		}
	}
	for i, line := range lines {
		out.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
		for _, owned := range insertAfter[i] {
			out.WriteString(owned + "\n")
		}
	}
	if len(tail) > 0 {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString(codexTailBegin + "\n")
		for _, line := range tail {
			out.WriteString(line + "\n")
		}
		out.WriteString(codexTailEnd + "\n")
	}
	rendered := []byte(out.String())
	if len(rendered) > policyFileLimit {
		return nil, nil, fmt.Errorf("rendered Codex requirements exceed %d bytes", policyFileLimit)
	}
	return rendered, conflicts, nil
}

func sameCodexPath(opts Options, left, right string) bool {
	if opts.goos() == "windows" {
		return strings.EqualFold(strings.TrimRight(left, `\`), strings.TrimRight(right, `\`))
	}
	return strings.TrimRight(left, "/") == strings.TrimRight(right, "/")
}

// countCodexOwnedGroups counts groups exactly matching DefenseClaw's
// registration for group.
func countCodexOwnedGroups(raw any, group connector.ManagedHookGroup, command string, opts Options) int {
	list, ok := raw.([]any)
	if !ok {
		return 0
	}
	count := 0
	for _, candidate := range list {
		entry, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		matcher, hasMatcher := entry["matcher"].(string)
		if group.Matcher == "" && hasMatcher || group.Matcher != "" && matcher != group.Matcher {
			continue
		}
		handlers, ok := entry["hooks"].([]any)
		if !ok || len(handlers) != 1 {
			continue
		}
		handler, ok := handlers[0].(map[string]any)
		if !ok || handler["type"] != "command" || handler["command"] != command {
			continue
		}
		if opts.goos() == "windows" && handler["command_windows"] != command {
			continue
		}
		if timeout, ok := tomlInt(handler["timeout"]); !ok || timeout != int64(group.Timeout) {
			continue
		}
		count++
	}
	return count
}

func tomlInt(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		return int64(v), v == float64(int64(v))
	}
	return 0, false
}

// inspectCodex fills state from a requirements document.
func inspectCodex(opts Options, raw []byte, policy config.ResolvedConnectorPolicy, state *State) error {
	cfg := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("parse Codex requirements: %w", err)
		}
	}
	groups, err := connector.ManagedHookGroupsForOS(codexConnector, opts.agentVersion(codexConnector), opts.goos())
	if err != nil {
		return err
	}
	hooksCfg, _ := cfg[codexHooksTable].(map[string]any)
	owned, foreign := 0, 0
	for _, group := range groups {
		count := countCodexOwnedGroups(hooksCfg[group.Event], group, codexHookCommandForEvent(opts, group.Event), opts)
		switch {
		case count == 0:
			state.conflict("hooks.%s has no DefenseClaw managed group", group.Event)
		case count > 1:
			state.conflict("hooks.%s has %d DefenseClaw managed groups, want exactly one", group.Event, count)
		}
		owned += count
	}
	for key, value := range hooksCfg {
		if list, ok := value.([]any); ok {
			for _, candidate := range list {
				if !codexGroupIsOwned(candidate, codexOwnedCommands(opts, groups)) {
					foreign++
				}
			}
		} else if key != "managed_dir" && key != "windows_managed_dir" {
			if key == "state" {
				state.conflict("hooks.state in machine requirements can change which managed hooks run; remove it")
			}
		}
	}
	state.OwnedEntries = owned
	state.ForeignEntries = foreign
	lock, present := cfg["allow_managed_hooks_only"].(bool)
	switch {
	case present && lock:
		state.EffectiveLock = config.ManagedHooksOnlyEnforce
	default:
		state.EffectiveLock = config.ManagedHooksOnlyPreserve
	}
	if policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce && state.EffectiveLock != config.ManagedHooksOnlyEnforce {
		state.conflict("allow_managed_hooks_only is not true; user and project Codex hooks can rewrite tool input after DefenseClaw inspects it")
	}
	if policy.ManagedHooksOnly == config.ManagedHooksOnlyPreserve && state.EffectiveLock != config.ManagedHooksOnlyEnforce {
		state.detail("managed_hooks_only: preserve — user and project Codex hooks still run and can rewrite tool input (updatedInput) after DefenseClaw approves it")
	}
	features, _ := cfg["features"].(map[string]any)
	if enabled, ok := features["hooks"].(bool); !ok || !enabled {
		state.conflict("features.hooks is not pinned true in machine requirements; a user config could turn hooks off")
	}
	if raw, present := hooksCfg[codexManagedDirKey(opts)]; !present || !sameCodexPath(opts, fmt.Sprint(raw), hookBinaryDir(opts)) {
		state.conflict("hooks.%s does not name DefenseClaw's hook directory %q", codexManagedDirKey(opts), hookBinaryDir(opts))
	}
	inspectCodexHigherSources(opts, policy, state)
	state.detail("cloud-managed Codex requirements (ChatGPT Business/Enterprise) are not visible locally; `enterprise policy verify --live --connector codex --user <user>` proves the effective policy")
	return nil
}

// codexHigherSources returns higher-ranked requirement layers as TOML
// documents keyed by a display name (macOS MDM requirements_toml_base64).
var codexHigherSources = platformCodexHigherSources

func inspectCodexHigherSources(opts Options, policy config.ResolvedConnectorPolicy, state *State) {
	sources, err := codexHigherSources(opts)
	if err != nil {
		state.conflict("inspect higher-precedence Codex requirements: %v", err)
		return
	}
	groups, err := connector.ManagedHookGroupsForOS(codexConnector, opts.agentVersion(codexConnector), opts.goos())
	if err != nil {
		return
	}
	for name, raw := range sources {
		cfg := map[string]any{}
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			state.conflict("%s is not valid TOML: %v", name, err)
			continue
		}
		hooksCfg, _ := cfg[codexHooksTable].(map[string]any)
		missing := 0
		for _, group := range groups {
			if countCodexOwnedGroups(hooksCfg[group.Event], group, codexHookCommandForEvent(opts, group.Event), opts) == 0 {
				missing++
			}
		}
		if missing == 0 {
			state.detail("%s embeds DefenseClaw's managed hooks", name)
			continue
		}
		message := fmt.Sprintf("%s outranks %s and does not include DefenseClaw's managed hooks; deploy the output of `defenseclaw-gateway enterprise policy export --connector codex --format plist` through the same MDM profile", name, "/etc/codex/requirements.toml")
		if policy.HigherPrecedenceSources == config.HigherPrecedenceWarn {
			state.detail("%s", message)
			continue
		}
		state.HigherPrecedence = append(state.HigherPrecedence, name)
		state.conflict("%s", message)
	}
}

func codexGroupIsOwned(candidate any, commands map[string]bool) bool {
	entry, ok := candidate.(map[string]any)
	if !ok {
		return false
	}
	handlers, ok := entry["hooks"].([]any)
	if !ok {
		return false
	}
	for _, raw := range handlers {
		if handler, ok := raw.(map[string]any); ok {
			if command, _ := handler["command"].(string); commands[command] {
				return true
			}
		}
	}
	return false
}

func newCodexState(opts Options, policy config.ResolvedConnectorPolicy, path string) State {
	return State{
		Connector:    codexConnector,
		Route:        RouteMachinePolicy,
		Ownership:    policy.Ownership,
		Lock:         policy.ManagedHooksOnly,
		ForeignHooks: policy.ForeignHooks,
		Paths:        []string{path},
	}
}

func (codexTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(codexConnector)
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newCodexState(opts, policy, path)
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		state.detail("ownership: off — DefenseClaw neither writes nor verifies Codex machine requirements")
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly {
		if err := inspectCodex(opts, current, policy, &state); err != nil {
			return state, err
		}
		if state.OwnedEntries == 0 {
			state.detail("missing_defenseclaw_hooks: deploy the output of `defenseclaw-gateway enterprise policy export --connector codex` through your policy tool")
		}
		state.finish()
		return state, nil
	}
	admin := stripCodexOwned(current)
	rendered, conflicts, err := renderCodex(opts, admin, policy)
	if err != nil {
		return state, err
	}
	if rendered == nil {
		for _, c := range conflicts {
			state.conflict("%s", c)
		}
		state.finish()
		return state, nil
	}
	probe := State{}
	if err := inspectCodex(opts, rendered, policy, &probe); err != nil {
		state.conflict("merged requirements.toml does not parse: %v; the administrator file layout is not mergeable (use ownership: verify_only)", err)
		state.finish()
		return state, nil
	}
	ownedBefore := false
	if exists {
		before := State{}
		if inspectCodex(opts, current, policy, &before) == nil {
			ownedBefore = before.OwnedEntries > 0
		}
	}
	changed, err := publishWithRecord(opts, codexConnector, path, current, exists, rendered, ownedBefore, codexStrip, &state)
	if err != nil {
		return state, err
	}
	state.Changed = changed
	if err := inspectCodex(opts, rendered, policy, &state); err != nil {
		return state, err
	}
	for _, c := range conflicts {
		if !containsString(state.Conflicts, c) {
			state.conflict("%s", c)
		}
	}
	state.finish()
	return state, nil
}

func (codexTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(codexConnector)
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newCodexState(opts, policy, path)
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if !exists {
		state.conflict("%s does not exist", path)
		state.finish()
		return state, nil
	}
	if err := inspectCodex(opts, current, policy, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (codexTarget) RemoveOwned(opts Options) (State, error) {
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: codexConnector, Route: RouteMachinePolicy, Paths: []string{path}}
	err = restoreOrStrip(opts, codexConnector, path, codexStrip, false, &state)
	return state, err
}

func (codexTarget) Export(opts Options, format string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	switch format {
	case "", "toml", "plist":
	default:
		return nil, fmt.Errorf("codex policy export supports formats toml and plist, not %q", format)
	}
	// Render against the current administrator file so the export is the
	// complete document to deploy (a TOML table cannot be declared twice,
	// so appending a snippet to a file that has [features] or [hooks]
	// would be invalid).
	var admin []byte
	if path, err := CodexRequirementsPath(opts); err == nil {
		if current, exists, readErr := readPolicyFile(opts, path); readErr == nil && exists {
			admin = stripCodexOwned(current)
		}
	}
	rendered, conflicts, err := renderCodex(opts, admin, opts.PolicyFor(codexConnector))
	if err != nil {
		return nil, err
	}
	if rendered == nil {
		return nil, fmt.Errorf("codex export: %s", strings.Join(conflicts, "; "))
	}
	if format == "plist" {
		// macOS MDM delivers requirements in the com.openai.codex domain as
		// base64 TOML; this layer outranks /etc/codex/requirements.toml.
		payload, err := json.Marshal(map[string]string{"requirements_toml_base64": base64.StdEncoding.EncodeToString(rendered)})
		if err != nil {
			return nil, err
		}
		return renderPlist(payload)
	}
	return rendered, nil
}

func containsString(list []string, value string) bool {
	for _, candidate := range list {
		if candidate == value {
			return true
		}
	}
	return false
}
