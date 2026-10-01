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

// Windows WSL agent sessions (enterprise.machine_policy.windows_wsl).
//
// An agent that runs inside a WSL 2 distribution is outside every Windows
// policy DefenseClaw publishes: the distribution reads its own
// /etc/claude-code, its own ~/.codex, and Windows endpoint sensors do not
// see the WSL VM. The standalone profile therefore keeps those sessions off
// where the vendors document a control, and reports what it cannot control.
//
// Vendor sources (checked 2026-09):
//   - Claude Desktop, https://code.claude.com/docs/en/admin-setup ("WSL
//     sessions"): HKLM\SOFTWARE\Policies\Claude\disableWslSessions; REG_SZ
//     false or REG_DWORD 0 enables WSL sessions (Desktop 1.19367.0 and
//     later), an HKCU value does not, Desktop re-reads it at each WSL session
//     start, and WSL Claude Code reads /etc/claude-code unless
//     wslInheritsWindowsSettings is deployed.
//   - Claude Desktop, https://claude.com/docs/third-party/claude-desktop/mdm:
//     any REG_SZ, REG_EXPAND_SZ or REG_DWORD value directly under
//     HKLM\SOFTWARE\Policies\Claude makes Desktop ignore HKCU
//     SOFTWARE\Policies\Claude; values in subkeys and REG_QWORD,
//     REG_MULTI_SZ or REG_BINARY values are invisible; local
//     %LOCALAPPDATA%\Claude-3p\configLibrary configuration is ignored once a
//     managed source sets a key other than the app-behavior keys.
//   - WSL, https://learn.microsoft.com/en-us/windows/wsl/intune:
//     HKLM\SOFTWARE\Policies\WSL\AllowWSL, 0 turns WSL off for every user.
//   - Codex IDE extension, https://learn.chatgpt.com/docs/ide/settings:
//     chatgpt.runCodexInWindowsSubsystemForLinux (default false) runs the
//     agent in WSL; chatgpt.cliExecutable is a developer-only override.
//   - Codex app, https://learn.chatgpt.com/docs/windows/windows-app: the
//     agent environment (Windows native or WSL) is an in-app setting with no
//     documented managed control or storage location.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ConnectorWSL names the Windows WSL agent-session row of `enterprise policy
// show|verify|export`. The lifecycle does not publish it as a connector; the
// standalone guardian reconciles it.
const ConnectorWSL = "wsl"

const (
	wslRecordName = "wsl"

	// ClaudeDesktopPolicyKey and the value that gates Claude Desktop WSL
	// sessions.
	ClaudeDesktopPolicyKey = `SOFTWARE\Policies\Claude`
	ClaudeDesktopWSLValue  = "disableWslSessions"
	// WSLPolicyKey and the value that turns WSL off machine-wide.
	WSLPolicyKey  = `SOFTWARE\Policies\WSL`
	WSLAllowValue = "AllowWSL"

	claudeCodeUserPolicyKey = `SOFTWARE\Policies\ClaudeCode`
	codexWSLSetting         = "chatgpt.runCodexInWindowsSubsystemForLinux"
	codexCLISetting         = "chatgpt.cliExecutable"
)

// Registry value types (winnt.h).
const (
	RegSZ       uint32 = 1
	RegExpandSZ uint32 = 2
	RegBinary   uint32 = 3
	RegDWORD    uint32 = 4
	RegMultiSZ  uint32 = 7
	RegQWORD    uint32 = 11
)

// RegValue is one registry value; String holds REG_SZ/REG_EXPAND_SZ data and
// Number REG_DWORD/REG_QWORD data.
type RegValue struct {
	Name   string `json:"name"`
	Type   uint32 `json:"type"`
	String string `json:"string,omitempty"`
	Number uint64 `json:"number,omitempty"`
}

// WSLRegistry is the registry access the WSL policy needs. Keys are paths
// under HKLM (64-bit view); UserValues reads the same path in every loaded
// user hive, keyed by SID.
type WSLRegistry interface {
	MachineValues(key string) (values []RegValue, exists bool, err error)
	UserValues(key string) (map[string][]RegValue, error)
	// MachineKeyWritableByUsers reports whether anyone other than
	// Administrators, SYSTEM or TrustedInstaller can change the key.
	MachineKeyWritableByUsers(key string) (bool, error)
	SetMachineValue(key string, value RegValue) error
	DeleteMachineValue(key, name string) error
	// ProfileHomes lists the local account profile folders.
	ProfileHomes() ([]string, error)
}

// wslRegistry is replaced in tests.
var wslRegistry = platformWSLRegistry

// claudeDesktopAppBehaviorKeys are the managed keys that do not turn off
// Claude Desktop's local third-party configuration.
var claudeDesktopAppBehaviorKeys = map[string]bool{
	"disableautoupdates": true, "autoupdaterenforcementhours": true, "updateviaupdateshost": true,
	"relaunchenforcementhours": true, "configrecheckintervalminutes": true,
	"egressproxyurl": true, "egressproxypacurl": true,
}

type wslOwnedValue struct {
	Key   string   `json:"key"`
	Value RegValue `json:"value"`
}

// wslOwnershipRecord lists the registry values DefenseClaw wrote, so removal
// deletes only values still exactly as written.
type wslOwnershipRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Connector     string          `json:"connector"`
	Values        []wslOwnedValue `json:"values,omitempty"`
	UpdatedAt     string          `json:"updated_at"`
}

func (r *wslOwnershipRecord) find(key, name string) *RegValue {
	for i := range r.Values {
		if strings.EqualFold(r.Values[i].Key, key) && strings.EqualFold(r.Values[i].Value.Name, name) {
			return &r.Values[i].Value
		}
	}
	return nil
}

func (r *wslOwnershipRecord) drop(key, name string) {
	kept := r.Values[:0]
	for _, owned := range r.Values {
		if !(strings.EqualFold(owned.Key, key) && strings.EqualFold(owned.Value.Name, name)) {
			kept = append(kept, owned)
		}
	}
	r.Values = kept
}

func loadWSLRecord(opts Options) (*wslOwnershipRecord, error) {
	path, err := recordPath(opts, wslRecordName)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &wslOwnershipRecord{Connector: wslRecordName}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record wslOwnershipRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if record.SchemaVersion != ownershipSchemaVersion || record.Connector != wslRecordName {
		return nil, fmt.Errorf("%s is not a WSL ownership record", path)
	}
	return &record, nil
}

func saveWSLRecord(opts Options, record *wslOwnershipRecord) error {
	if len(record.Values) == 0 {
		return deleteRecord(opts, wslRecordName)
	}
	path, err := recordPath(opts, wslRecordName)
	if err != nil {
		return err
	}
	if err := ensurePrivateDir(opts.StateDir); err != nil {
		return err
	}
	record.SchemaVersion, record.Connector = ownershipSchemaVersion, wslRecordName
	record.UpdatedAt = opts.now().Format(time.RFC3339)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(opts, path, append(data, '\n'), false)
}

func findRegValue(values []RegValue, name string) *RegValue {
	for i := range values {
		if strings.EqualFold(values[i].Name, name) {
			return &values[i]
		}
	}
	return nil
}

func sameRegValue(a, b RegValue) bool {
	if a.Type != b.Type || !strings.EqualFold(a.Name, b.Name) {
		return false
	}
	switch a.Type {
	case RegSZ, RegExpandSZ:
		return a.String == b.String
	case RegDWORD, RegQWORD:
		return a.Number == b.Number
	}
	return false
}

// claudeDesktopVisible reports whether Claude Desktop reads a value type.
func claudeDesktopVisible(value RegValue) bool {
	return value.Type == RegSZ || value.Type == RegExpandSZ || value.Type == RegDWORD
}

// wslGateBool reads disableWslSessions as Claude Desktop documents it.
func wslGateBool(value RegValue) (bool, bool) {
	switch value.Type {
	case RegSZ, RegExpandSZ:
		switch strings.ToLower(strings.TrimSpace(value.String)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	case RegDWORD:
		return value.Number != 0, true
	}
	return false, false
}

func describeRegValue(value RegValue) string {
	switch value.Type {
	case RegSZ, RegExpandSZ:
		return fmt.Sprintf("%q", value.String)
	case RegDWORD, RegQWORD:
		return fmt.Sprintf("%d", value.Number)
	}
	return fmt.Sprintf("(registry type %d)", value.Type)
}

func wslPolicy(opts Options) config.EnterpriseWindowsWSLPolicy {
	return config.EnterpriseMachinePolicyConfig{WindowsWSL: opts.WSL}.WSL()
}

func wslState() State {
	return State{
		Connector: ConnectorWSL,
		Route:     RouteMachinePolicy,
		Ownership: config.MachinePolicyOwnershipMerge,
		Paths: []string{
			`HKLM\` + ClaudeDesktopPolicyKey + `\` + ClaudeDesktopWSLValue,
			`HKLM\` + WSLPolicyKey + `\` + WSLAllowValue,
		},
	}
}

// PublishWindowsWSL reconciles the WSL registry policy: it writes
// disableWslSessions (agent_sessions: block) where Claude Desktop's hive rule
// makes that safe and AllowWSL=0 (platform: disable), and retires values it
// wrote that the policy no longer asks for. The standalone guardian runs it
// every reconcile.
func PublishWindowsWSL(opts Options) (State, error) {
	return reconcileWSL(opts, nil, true)
}

// VerifyWindowsWSL inspects the WSL policy without writing; homes are the
// enrolled profiles whose editor settings it also checks.
func VerifyWindowsWSL(opts Options, homes []string) (State, error) {
	return reconcileWSL(opts, homes, false)
}

func reconcileWSL(opts Options, homes []string, write bool) (State, error) {
	state := wslState()
	if opts.goos() != "windows" {
		return state, errors.New("the WSL agent-session policy applies only to Windows")
	}
	record, err := loadWSLRecord(opts)
	if err != nil {
		return state, err
	}
	reg := wslRegistry()
	policy := wslPolicy(opts)
	dirty := false
	save := func() error {
		if !dirty || !write {
			return nil
		}
		return saveWSLRecord(opts, record)
	}
	// ours reports whether the current value is exactly what DefenseClaw
	// wrote; a record entry for a value someone else changed is dropped.
	ours := func(key string, current *RegValue, name string) bool {
		owned := record.find(key, name)
		if owned == nil {
			return false
		}
		if current != nil && sameRegValue(*owned, *current) {
			return true
		}
		record.drop(key, name)
		dirty = true
		return false
	}

	platformOff, err := reconcileWSLPlatform(reg, policy, record, ours, write, &dirty, &state)
	if err != nil {
		return state, errors.Join(err, save())
	}
	var gaps []wslGap
	blocked, err := reconcileClaudeDesktopGate(opts, reg, policy, record, ours, write, &dirty, &state, &gaps)
	if err != nil {
		return state, errors.Join(err, save())
	}
	if err := save(); err != nil {
		return state, err
	}
	accepted := policy.AgentSessions == config.WSLAgentSessionsAllow
	inherit, inheritErr := wslInheritSources(opts, reg)
	if inheritErr != nil {
		gaps = append(gaps, wslGap{text: fmt.Sprintf("cannot check wslInheritsWindowsSettings: %v", inheritErr)})
	}
	for _, source := range inherit {
		if blocked || platformOff {
			state.detail("%s sets wslInheritsWindowsSettings; it has no effect while WSL sessions are off", source)
		} else {
			gaps = append(gaps, wslGap{text: fmt.Sprintf("%s sets wslInheritsWindowsSettings: WSL Claude Code sessions read the Windows managed settings, whose DefenseClaw hook commands do not run inside WSL", source)})
		}
	}
	for _, gap := range gaps {
		switch {
		case platformOff:
			state.detail("%s (WSL is off, so no WSL session starts)", gap.text)
		case accepted:
			state.detail("%s (accepted: agent_sessions is allow)", gap.text)
		case gap.advisory:
			state.Pending = append(state.Pending, gap.text)
		default:
			state.conflict("%s", gap.text)
		}
	}
	if !platformOff && !accepted {
		state.Pending = append(state.Pending, "Codex app: Settings > Agent environment can run the agent in WSL; OpenAI documents no managed control for it, so DefenseClaw cannot see or block that choice (set platform: disable to turn WSL off)")
	}
	if policy.EditorSettings != config.WSLEditorSettingsAllow && !platformOff {
		for _, home := range homes {
			findings, err := ScanWSLEditorSettings(home)
			if err != nil {
				state.conflict("editor settings under %s: %v", home, err)
			}
			for _, finding := range findings {
				if finding.WSL {
					fix := "the guardian resets it to false at its next pass"
					if policy.EditorSettings == config.WSLEditorSettingsReport {
						fix = "editor_settings is report, so DefenseClaw leaves it"
					}
					state.conflict("%s sets %s: true, which runs the Codex IDE extension's agent in WSL; %s", finding.Path, codexWSLSetting, fix)
				}
				if finding.CLIExecutable {
					state.detail("%s sets %s, a developer-only override of the Codex binary the extension runs", finding.Path, codexCLISetting)
				}
			}
		}
	}
	if accepted {
		state.detail("agent_sessions is allow: Claude Desktop WSL sessions and Codex in WSL run without DefenseClaw")
	}
	sort.Strings(state.HigherPrecedence)
	state.Covered = len(state.Conflicts) == 0 && len(state.HigherPrecedence) == 0
	return state, nil
}

func reconcileWSLPlatform(reg WSLRegistry, policy config.EnterpriseWindowsWSLPolicy, record *wslOwnershipRecord, ours func(string, *RegValue, string) bool, write bool, dirty *bool, state *State) (bool, error) {
	values, _, err := reg.MachineValues(WSLPolicyKey)
	if err != nil {
		return false, fmt.Errorf("read HKLM\\%s: %w", WSLPolicyKey, err)
	}
	path := `HKLM\` + WSLPolicyKey + `\` + WSLAllowValue
	current := findRegValue(values, WSLAllowValue)
	mine := ours(WSLPolicyKey, current, WSLAllowValue)
	off := current != nil && current.Type == RegDWORD && current.Number == 0
	if policy.Platform != config.WSLPlatformDisable {
		switch {
		case mine && write:
			if err := reg.DeleteMachineValue(WSLPolicyKey, WSLAllowValue); err != nil {
				return false, fmt.Errorf("remove %s: %w", path, err)
			}
			record.drop(WSLPolicyKey, WSLAllowValue)
			*dirty, state.Changed = true, true
			state.detail("removed %s=0 that DefenseClaw wrote (platform is leave)", path)
			return false, nil
		case mine:
			state.Pending = append(state.Pending, fmt.Sprintf("the guardian removes %s=0 that DefenseClaw wrote (platform is leave)", path))
		case off:
			state.detail("administrator policy %s=0 turns WSL off for every account", path)
		}
		return off, nil
	}
	switch {
	case off:
		if mine {
			state.OwnedEntries++
			state.detail("%s=0 (DefenseClaw) turns WSL off for every account", path)
		} else {
			state.detail("administrator policy %s=0 turns WSL off for every account", path)
		}
		return true, nil
	case current != nil:
		state.conflict("administrator policy %s=%s keeps WSL on; platform: disable does not replace administrator values", path, describeRegValue(*current))
		return false, nil
	case !write:
		state.conflict("%s is not set; the guardian writes 0 at its next pass (platform is disable)", path)
		return false, nil
	}
	value := RegValue{Name: WSLAllowValue, Type: RegDWORD, Number: 0}
	if err := reg.SetMachineValue(WSLPolicyKey, value); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	record.Values = append(record.Values, wslOwnedValue{Key: WSLPolicyKey, Value: value})
	*dirty, state.Changed = true, true
	state.OwnedEntries++
	state.detail("wrote %s=0: WSL is off for every account", path)
	return true, nil
}

// wslGap is one way agent sessions in WSL can escape DefenseClaw. A gap
// fails verify unless it is advisory: nothing known turns WSL sessions on,
// and DefenseClaw only declined to add its own explicit gate.
type wslGap struct {
	text     string
	advisory bool
}

func reconcileClaudeDesktopGate(opts Options, reg WSLRegistry, policy config.EnterpriseWindowsWSLPolicy, record *wslOwnershipRecord, ours func(string, *RegValue, string) bool, write bool, dirty *bool, state *State, gaps *[]wslGap) (bool, error) {
	values, keyExists, err := reg.MachineValues(ClaudeDesktopPolicyKey)
	if err != nil {
		return false, fmt.Errorf("read HKLM\\%s: %w", ClaudeDesktopPolicyKey, err)
	}
	path := `HKLM\` + ClaudeDesktopPolicyKey + `\` + ClaudeDesktopWSLValue
	current := findRegValue(values, ClaudeDesktopWSLValue)
	mine := ours(ClaudeDesktopPolicyKey, current, ClaudeDesktopWSLValue)
	if policy.AgentSessions == config.WSLAgentSessionsAllow {
		if mine {
			if !write {
				state.Pending = append(state.Pending, fmt.Sprintf("the guardian removes %s that DefenseClaw wrote (agent_sessions is allow)", path))
				return true, nil
			}
			if err := reg.DeleteMachineValue(ClaudeDesktopPolicyKey, ClaudeDesktopWSLValue); err != nil {
				return false, fmt.Errorf("remove %s: %w", path, err)
			}
			record.drop(ClaudeDesktopPolicyKey, ClaudeDesktopWSLValue)
			*dirty, state.Changed = true, true
			state.detail("removed %s that DefenseClaw wrote (agent_sessions is allow)", path)
			return false, nil
		}
		blocked := false
		if current != nil {
			blocked, _ = wslGateBool(*current)
		}
		return blocked, nil
	}
	if current != nil {
		on, known := wslGateBool(*current)
		switch {
		case known && on:
			if mine {
				state.OwnedEntries++
				state.detail("%s=true (DefenseClaw) keeps Claude Desktop WSL sessions off", path)
				// The conditions DefenseClaw wrote the gate under can stop
				// holding (the organization's own values removed, HKCU
				// policy or local configuration added). The gate stays,
				// since removing it turns WSL sessions back on, but the
				// row is not covered while it overrides account policy.
				refusal, err := claudeDesktopGateRefusal(reg, policy, withoutRegValue(values, ClaudeDesktopWSLValue), keyExists)
				if err != nil {
					return true, err
				}
				if refusal != "" {
					state.conflict("DefenseClaw's %s no longer meets its write conditions: %s", path, refusal)
				}
			} else {
				state.detail("administrator policy %s=%s keeps Claude Desktop WSL sessions off", path, describeRegValue(*current))
			}
			return true, nil
		case known:
			*gaps = append(*gaps, wslGap{text: fmt.Sprintf("administrator policy %s=%s turns Claude Desktop WSL sessions on, and DefenseClaw hooks do not run inside WSL; remove the value, or set enterprise.machine_policy.windows_wsl.agent_sessions: allow to accept this", path, describeRegValue(*current))})
		default:
			*gaps = append(*gaps, wslGap{text: fmt.Sprintf("%s has registry type %d, which Claude Desktop does not read; deliver it as REG_SZ true", path, current.Type)})
		}
		return false, nil
	}
	refusal, err := claudeDesktopGateRefusal(reg, policy, values, keyExists)
	if err != nil {
		return false, err
	}
	switch {
	case refusal.text != "" && refusal.advisory:
		// Unset, the gate falls back to Claude Desktop's own default, which
		// keeps WSL sessions off on devices it treats as organization-managed.
		// Nothing known turns them on, so this is reported with the step that
		// makes the gate explicit, not as a verify failure.
		refusal.text = fmt.Sprintf("%s is not set, so Claude Desktop's default applies (WSL sessions off on devices it treats as organization-managed): %s", path, refusal.text)
		*gaps = append(*gaps, refusal)
		return false, nil
	case refusal.text != "":
		*gaps = append(*gaps, refusal)
		return false, nil
	case !write:
		*gaps = append(*gaps, wslGap{text: fmt.Sprintf("%s is not set; the guardian writes it at its next pass", path)})
		return false, nil
	}
	value := RegValue{Name: ClaudeDesktopWSLValue, Type: RegSZ, String: "true"}
	if err := reg.SetMachineValue(ClaudeDesktopPolicyKey, value); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	record.Values = append(record.Values, wslOwnedValue{Key: ClaudeDesktopPolicyKey, Value: value})
	*dirty, state.Changed = true, true
	state.OwnedEntries++
	state.detail("wrote %s=true: Claude Desktop WSL sessions are off", path)
	return true, nil
}

// withoutRegValue is values without the value named name.
func withoutRegValue(values []RegValue, name string) []RegValue {
	out := make([]RegValue, 0, len(values))
	for _, value := range values {
		if !strings.EqualFold(value.Name, name) {
			out = append(out, value)
		}
	}
	return out
}

// claudeDesktopGateRefusal says why DefenseClaw must not add
// disableWslSessions to HKLM\SOFTWARE\Policies\Claude, or returns an empty
// gap. The refusal is advisory when DefenseClaw only declines so it does not
// displace other Claude Desktop policy the administrator did not ask it to
// override (merge); an unmet claude_desktop_key: create, or a key a standard
// account can change, fails verify.
func claudeDesktopGateRefusal(reg WSLRegistry, policy config.EnterpriseWindowsWSLPolicy, values []RegValue, keyExists bool) (wslGap, error) {
	create := policy.ClaudeDesktopKey == config.WSLClaudeDesktopKeyCreate
	// A key a standard account can change lets that account turn WSL
	// sessions on whatever DefenseClaw writes.
	if keyExists {
		open, err := reg.MachineKeyWritableByUsers(ClaudeDesktopPolicyKey)
		if err != nil {
			return wslGap{}, fmt.Errorf("inspect HKLM\\%s: %w", ClaudeDesktopPolicyKey, err)
		}
		if open {
			return wslGap{text: `HKLM\` + ClaudeDesktopPolicyKey + ` grants write access beyond Administrators, SYSTEM and TrustedInstaller, so a standard account can turn Claude Desktop WSL sessions on; restrict the key to those principals`}, nil
		}
	}
	present, appBehaviorOnly := false, true
	for _, value := range values {
		if !claudeDesktopVisible(value) {
			continue
		}
		present = true
		if !claudeDesktopAppBehaviorKeys[strings.ToLower(value.Name)] {
			appBehaviorOnly = false
		}
	}
	if !present && !create {
		return wslGap{advisory: true, text: `HKLM\` + ClaudeDesktopPolicyKey + ` holds no machine policy, and any value there makes Claude Desktop ignore every account's HKCU policy and local third-party configuration; to set the gate explicitly, deploy the output of "defenseclaw enterprise policy export --connector wsl" with the organization's Claude Desktop policy, or set enterprise.machine_policy.windows_wsl.claude_desktop_key: create`}, nil
	}
	if !present {
		users, err := reg.UserValues(ClaudeDesktopPolicyKey)
		if err != nil {
			return wslGap{}, fmt.Errorf("read user Claude Desktop policy: %w", err)
		}
		count := 0
		for _, userValues := range users {
			for _, value := range userValues {
				if claudeDesktopVisible(value) {
					count++
					break
				}
			}
		}
		if count > 0 {
			return wslGap{text: fmt.Sprintf("claude_desktop_key is create, but %d signed-in account(s) have HKCU Claude Desktop policy that a new HKLM value would override; move it to HKLM first", count)}, nil
		}
	}
	if appBehaviorOnly {
		homes, err := reg.ProfileHomes()
		if err != nil {
			return wslGap{}, fmt.Errorf("list profiles: %w", err)
		}
		count := 0
		for _, home := range homes {
			entries, err := os.ReadDir(filepath.Join(home, "AppData", "Local", "Claude-3p", "configLibrary"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return wslGap{}, err
			}
			if len(entries) > 0 {
				count++
			}
		}
		if count > 0 {
			return wslGap{advisory: !create, text: fmt.Sprintf("%d account(s) have local Claude Desktop third-party configuration (Claude-3p\\configLibrary) that Claude Desktop ignores once HKLM sets a key other than its app-behavior keys; move it to machine policy first, and the guardian then adds the gate", count)}, nil
		}
	}
	return wslGap{}, nil
}

// wslInheritSources names the Claude Code managed sources that set
// wslInheritsWindowsSettings: true. Replaced in tests.
var wslInheritSources = func(opts Options, reg WSLRegistry) ([]string, error) {
	var names []string
	inherits := func(doc *object) bool {
		value, ok := doc.get("wslInheritsWindowsSettings")
		on, isBool := value.(bool)
		return ok && isBool && on
	}
	higher, err := claudeHigherSources(opts)
	if err != nil {
		return nil, err
	}
	for _, source := range higher {
		if inherits(source.doc) {
			names = append(names, source.name)
		}
	}
	files, err := readClaudeFileSources(opts)
	if err != nil {
		return names, err
	}
	for _, source := range files {
		if inherits(source.doc) {
			names = append(names, source.name)
		}
	}
	users, err := reg.UserValues(claudeCodeUserPolicyKey)
	if err != nil {
		return names, err
	}
	sids := make([]string, 0, len(users))
	for sid := range users {
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	for _, sid := range sids {
		value := findRegValue(users[sid], "Settings")
		if value == nil || (value.Type != RegSZ && value.Type != RegExpandSZ) {
			continue
		}
		if doc, err := decodeOrderedObject([]byte(value.String)); err == nil && inherits(doc) {
			names = append(names, `HKU\`+sid+`\`+claudeCodeUserPolicyKey+`\Settings`)
		}
	}
	return names, nil
}

// RemoveWindowsWSL deletes the registry values DefenseClaw recorded writing
// (uninstall and rollback). A value someone changed since is left.
func RemoveWindowsWSL(opts Options) (State, error) {
	state := wslState()
	if opts.goos() != "windows" {
		return state, errors.New("RemoveWindowsWSL applies only to Windows")
	}
	record, err := loadWSLRecord(opts)
	if err != nil || len(record.Values) == 0 {
		return state, err
	}
	reg := wslRegistry()
	for _, owned := range record.Values {
		values, _, err := reg.MachineValues(owned.Key)
		if err != nil {
			return state, err
		}
		path := `HKLM\` + owned.Key + `\` + owned.Value.Name
		current := findRegValue(values, owned.Value.Name)
		if current == nil || !sameRegValue(*current, owned.Value) {
			state.detail("left %s: it changed after DefenseClaw wrote it", path)
			continue
		}
		if err := reg.DeleteMachineValue(owned.Key, owned.Value.Name); err != nil {
			return state, fmt.Errorf("remove %s: %w", path, err)
		}
		state.Changed = true
		state.detail("removed %s", path)
	}
	return state, deleteRecord(opts, wslRecordName)
}

// ExportWSL renders the registry values the WSL policy asks for, for an
// administrator's own policy tool: reg (default), json or intune
// (intune-settings-catalog).
func ExportWSL(opts Options, format string) ([]byte, error) {
	policy := wslPolicy(opts)
	var values []wslOwnedValue
	if policy.AgentSessions == config.WSLAgentSessionsBlock {
		values = append(values, wslOwnedValue{Key: ClaudeDesktopPolicyKey, Value: RegValue{Name: ClaudeDesktopWSLValue, Type: RegSZ, String: "true"}})
	}
	if policy.Platform == config.WSLPlatformDisable {
		values = append(values, wslOwnedValue{Key: WSLPolicyKey, Value: RegValue{Name: WSLAllowValue, Type: RegDWORD, Number: 0}})
	}
	if len(values) == 0 {
		return nil, errors.New("wsl export: nothing to export while agent_sessions is allow and platform is leave")
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "reg":
		var out strings.Builder
		out.WriteString("Windows Registry Editor Version 5.00\r\n")
		for _, owned := range values {
			fmt.Fprintf(&out, "\r\n[HKEY_LOCAL_MACHINE\\%s]\r\n", owned.Key)
			if owned.Value.Type == RegDWORD {
				fmt.Fprintf(&out, "%q=dword:%08x\r\n", owned.Value.Name, owned.Value.Number)
			} else {
				fmt.Fprintf(&out, "%q=%q\r\n", owned.Value.Name, owned.Value.String)
			}
		}
		return []byte(out.String()), nil
	case "json", "intune", "intune-settings-catalog":
		type entry struct {
			Hive  string `json:"hive"`
			Key   string `json:"key"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value any    `json:"value"`
		}
		doc := struct {
			Platform    string  `json:"platform"`
			Description string  `json:"description"`
			Registry    []entry `json:"registry"`
		}{
			Platform:    "windows",
			Description: "Deploy as SYSTEM (an Intune Remediation or Win32 app script, or Group Policy). A value under HKLM\\SOFTWARE\\Policies\\Claude makes Claude Desktop ignore HKCU policy and local third-party configuration: add disableWslSessions to the Claude Desktop policy you already deploy. AllowWSL=0 turns WSL off for every account.",
		}
		for _, owned := range values {
			item := entry{Hive: "HKEY_LOCAL_MACHINE", Key: owned.Key, Name: owned.Value.Name, Type: "REG_SZ", Value: owned.Value.String}
			if owned.Value.Type == RegDWORD {
				item.Type, item.Value = "REG_DWORD", owned.Value.Number
			}
			doc.Registry = append(doc.Registry, item)
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	}
	return nil, fmt.Errorf("wsl policy export supports reg, json and intune (intune-settings-catalog), not %q", format)
}

// WSLEditorFinding is one editor settings file that sets the Codex IDE
// extension's WSL options.
type WSLEditorFinding struct {
	Path          string `json:"path"`
	WSL           bool   `json:"wsl"`
	CLIExecutable bool   `json:"cli_executable,omitempty"`
	Repaired      bool   `json:"repaired,omitempty"`
}

// ScanWSLEditorSettings reads home's VS Code, VS Code Insiders and Cursor
// user settings (and their profiles) for the Codex IDE extension's WSL mode.
func ScanWSLEditorSettings(home string) ([]WSLEditorFinding, error) {
	return wslEditorPass(home, false)
}

// RepairWSLEditorSettings is ScanWSLEditorSettings that also rewrites
// chatgpt.runCodexInWindowsSubsystemForLinux: true to false in place,
// keeping every other byte (comments, trailing commas, line endings). Run it
// as the profile's user.
func RepairWSLEditorSettings(home string) ([]WSLEditorFinding, error) {
	return wslEditorPass(home, true)
}

func wslEditorSettingsFiles(home string) []string {
	var files []string
	for _, product := range []string{"Code", "Code - Insiders", "Cursor"} {
		user := filepath.Join(home, "AppData", "Roaming", product, "User")
		files = append(files, filepath.Join(user, "settings.json"))
		entries, _ := os.ReadDir(filepath.Join(user, "profiles"))
		for _, entry := range entries {
			if entry.IsDir() {
				files = append(files, filepath.Join(user, "profiles", entry.Name(), "settings.json"))
			}
		}
	}
	return files
}

func wslEditorPass(home string, repair bool) ([]WSLEditorFinding, error) {
	var findings []WSLEditorFinding
	var errs []error
	for _, path := range wslEditorSettingsFiles(home) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !info.Mode().IsRegular() || info.Size() > policyFileLimit {
			errs = append(errs, fmt.Errorf("%s is not a regular settings file", path))
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		wslTrue, cli, err := scanCodexEditorSettings(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		finding := WSLEditorFinding{Path: path, WSL: len(wslTrue) > 0, CLIExecutable: cli}
		if finding.WSL && repair {
			if err := rewriteEditorSettings(path, data, wslTrue, info.Mode().Perm()); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			} else {
				finding.Repaired = true
			}
		}
		if finding.WSL || finding.CLIExecutable {
			findings = append(findings, finding)
		}
	}
	return findings, errors.Join(errs...)
}

// rewriteEditorSettings replaces each `true` at offsets with `false` and
// swaps the file in, unless the editor changed it since data was read.
func rewriteEditorSettings(path string, data []byte, offsets []int, perm os.FileMode) error {
	var out bytes.Buffer
	last := 0
	for _, offset := range offsets {
		out.Write(data[last:offset])
		out.WriteString("false")
		last = offset + len("true")
	}
	out.Write(data[last:])
	temp, err := os.CreateTemp(filepath.Dir(path), ".settings-defenseclaw-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(out.Bytes()); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	again, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, data) {
		return errors.New("changed while being repaired; the next pass retries")
	}
	return os.Rename(name, path)
}

type jsoncToken struct {
	kind       byte // one of {}[]:, or 's' (string) or 'l' (literal)
	start, end int
}

func jsoncTokens(data []byte) ([]jsoncToken, error) {
	var tokens []jsoncToken
	i := 0
	if bytes.HasPrefix(data, []byte("\xEF\xBB\xBF")) {
		i = 3
	}
	for i < len(data) {
		c := data[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return nil, errors.New("unterminated comment")
			}
			i += end + 4
		case strings.IndexByte("{}[]:,", c) >= 0:
			tokens = append(tokens, jsoncToken{kind: c, start: i, end: i + 1})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(data) && data[j] != '"'; j++ {
				if data[j] == '\\' {
					j++
				} else if data[j] == '\n' {
					return nil, errors.New("unterminated string")
				}
			}
			if j >= len(data) {
				return nil, errors.New("unterminated string")
			}
			tokens = append(tokens, jsoncToken{kind: 's', start: i, end: j + 1})
			i = j + 1
		default:
			j := i
			for j < len(data) && (data[j] == '-' || data[j] == '+' || data[j] == '.' ||
				(data[j] >= '0' && data[j] <= '9') || (data[j] >= 'a' && data[j] <= 'z') || (data[j] >= 'A' && data[j] <= 'Z')) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected byte at offset %d", i)
			}
			tokens = append(tokens, jsoncToken{kind: 'l', start: i, end: j})
			i = j
		}
	}
	return tokens, nil
}

// scanCodexEditorSettings finds, in a VS Code JSONC settings document, the
// offsets of each top-level runCodexInWindowsSubsystemForLinux `true` and
// whether a non-empty cliExecutable is set.
func scanCodexEditorSettings(data []byte) ([]int, bool, error) {
	tokens, err := jsoncTokens(data)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, false, nil
	}
	if tokens[0].kind != '{' {
		return nil, false, errors.New("settings are not a JSON object")
	}
	var wslTrue []int
	cli := false
	depth := 0
	for k, token := range tokens {
		switch token.kind {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 || (depth == 0 && k != len(tokens)-1) {
				return nil, false, errors.New("settings are not one JSON object")
			}
		case 's':
			if depth != 1 || (tokens[k-1].kind != '{' && tokens[k-1].kind != ',') || k+2 >= len(tokens) || tokens[k+1].kind != ':' {
				continue
			}
			var key string
			if json.Unmarshal(data[token.start:token.end], &key) != nil {
				continue
			}
			value := tokens[k+2]
			switch key {
			case codexWSLSetting:
				if value.kind == 'l' && string(data[value.start:value.end]) == "true" {
					wslTrue = append(wslTrue, value.start)
				}
			case codexCLISetting:
				var path string
				if value.kind == 's' && json.Unmarshal(data[value.start:value.end], &path) == nil && strings.TrimSpace(path) != "" {
					cli = true
				}
			}
		}
	}
	if depth != 0 {
		return nil, false, errors.New("settings are not one JSON object")
	}
	return wslTrue, cli, nil
}
