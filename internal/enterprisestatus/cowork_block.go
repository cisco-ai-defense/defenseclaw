// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Claude Cowork runs its agent loop as the Claude Code engine Claude Desktop
// bundles, on the device, as the user. The engine loads Claude Code machine
// policy, so DefenseClaw's claudecode machine-policy hooks run for Cowork's
// tool calls (1.0.8 live tests, managed macOS and Windows, Claude Desktop
// 4.16336.0, engine 2.1.317, third-party inference: the calls reached the
// gateway with surface cowork): Cowork is a surface of the claudecode
// connector, not a connector of its own. The cowork block says whether
// DefenseClaw's side of that is configured, how many hook calls reported
// themselves as Cowork and when each enrolled account last sent one
// (caller-reported attribution: any local process can send it, so it is not
// proof that the hooks ran in Cowork), whether customers' own Cowork plugin
// hooks are meant to run next to it (managed_hooks_only) and the trust of
// each account's Claude Desktop engine build. It is on status and verify of the
// standalone profile only. It names accounts, so it is built only for an
// administrator: root on Linux and macOS, an elevated administrator on
// Windows.

// Reasons the cowork block is not configured.
const (
	CoworkReasonConnectorDisabled  = "claudecode_not_enabled"
	CoworkReasonMachinePolicyUnset = "claudecode_machine_policy_not_in_place"
	// CoworkReasonDesktopRefused: enterprise.enrollment.unverified_versions
	// is refuse for claudecode and Claude Desktop's surface (where Cowork
	// runs) is not live-verified, so the gateway refuses Cowork's calls.
	CoworkReasonDesktopRefused = "claudecode_desktop_surface_refused"
)

// CoworkAccountsMax bounds CoworkState.Accounts.
const CoworkAccountsMax = 64

// CoworkState is the cowork block.
type CoworkState struct {
	// Configured: claudecode is enabled, DefenseClaw's Claude Code machine
	// policy hooks are in place (connectors.claudecode.hooks_installed all)
	// and the gateway does not refuse the Claude Desktop surface.
	Configured bool `json:"configured"`
	// Reason is why Configured is false (a CoworkReason code).
	Reason string `json:"reason,omitempty"`
	// ManagedHooksOnly is the claudecode machine policy managed_hooks_only:
	// enforce (the default) keeps only managed hooks, so customers' own
	// Cowork plugin hooks are meant not to run (Anthropic's documented
	// behaviour; the 1.0.8 live tests did not cover plugin hooks); preserve
	// lets them run.
	ManagedHooksOnly string `json:"managed_hooks_only,omitempty"`
	// Requests and LastEventAt are the gateway's machine-wide hook calls
	// that reported themselves as Cowork (caller-reported) since it started
	// (/health).
	Requests    int64  `json:"requests"`
	LastEventAt string `json:"last_event_at,omitempty"`
	// AccountsKnown says the audit store answered the per-account lookup;
	// Accounts are then the enrolled accounts and every account with a
	// Cowork event, each with its last one (absent: never).
	AccountsKnown bool            `json:"accounts_known"`
	Accounts      []CoworkAccount `json:"accounts,omitempty"`
	// AccountsTruncated: more accounts exist than Accounts lists (the
	// CoworkAccountsMax bound, or the audit lookup's own row bound).
	AccountsTruncated bool `json:"accounts_truncated,omitempty"`
	// ClaudeDesktop is the Claude Desktop installs of every account
	// enrollment includes and the trust of their engine builds, read from
	// disk when status or verify runs (no running engine needed). On Linux
	// and macOS Claude Code is a machine-policy connector, so such an
	// account has no enrollment row and was shown nowhere (cowork-1-0-8
	// GAP-0031); on Windows these are the enrolled accounts, and trust is
	// the Authenticode check enrolment makes (GAP-0057). Absent when not
	// run as root or as an elevated administrator.
	ClaudeDesktop *CoworkDesktopState `json:"claude_desktop,omitempty"`
}

// Trust results of a Claude Desktop engine build (CoworkDesktopInstall.Trust).
const (
	// CoworkEngineTrusted: the code signature verifies as Anthropic's
	// Claude Code (macOS: Developer ID team Q6L2SF6YDW, identifier
	// com.anthropic.claude-code, and its Info.plist names the folder's
	// version; Windows: an Authenticode signature by Anthropic whose signed
	// file version is the folder's).
	CoworkEngineTrusted = "trusted"
	// CoworkEngineUntrusted: the build has a signature that does not verify
	// or names another signer, its version does not match its folder, or
	// the check could not run (Reason says which).
	CoworkEngineUntrusted = "untrusted"
	// CoworkEngineUnsigned: the build has no signature (every Linux build:
	// Linux builds carry no vendor signature).
	CoworkEngineUnsigned = "unsigned"
	// CoworkEngineNotFound: the data folder holds no engine build.
	CoworkEngineNotFound = "not_found"
)

// CoworkDesktopState is the claude_desktop member of the cowork block.
type CoworkDesktopState struct {
	// AccountsKnown says the enumerator's account record was read (or is
	// absent, and only the manifest names accounts).
	AccountsKnown bool                   `json:"accounts_known"`
	Accounts      []CoworkDesktopAccount `json:"accounts,omitempty"`
	// AccountsTruncated: more accounts are included than Accounts lists
	// (CoworkAccountsMax).
	AccountsTruncated bool `json:"accounts_truncated,omitempty"`
	// Trusted, Untrusted, Unsigned and NotFound count the listed installs
	// by the trust of their newest engine build.
	Trusted   int `json:"trusted"`
	Untrusted int `json:"untrusted"`
	Unsigned  int `json:"unsigned"`
	NotFound  int `json:"not_found"`
}

// CoworkDesktopAccount is one included account's Claude Desktop installs.
type CoworkDesktopAccount struct {
	Account string `json:"account"`
	// Installs are the account's Claude Desktop data folders that exist,
	// one per deployment (internal/claudedesktop); none: no Claude Desktop.
	Installs []CoworkDesktopInstall `json:"installs,omitempty"`
	// Reason says why the account's folders were not checked, or not all
	// of them (Windows: for example no signed-in session for an MDM run);
	// absent when they were.
	Reason string `json:"reason,omitempty"`
}

// CoworkDesktopInstall is one Claude Desktop data folder and the newest
// engine build in it.
type CoworkDesktopInstall struct {
	// Deployment is "1p" (Claude account) or "3p" (third-party inference).
	Deployment string `json:"deployment"`
	Path       string `json:"path"`
	// EngineVersion and EnginePath are the newest engine build (absent
	// when Trust is not_found).
	EngineVersion string `json:"engine_version,omitempty"`
	EnginePath    string `json:"engine_path,omitempty"`
	Trust         string `json:"trust"`
	// Reason says why the build is not trusted, or a limit of a trusted one.
	Reason string `json:"reason,omitempty"`
}

// Count adds install to the trust counts.
func (d *CoworkDesktopState) Count(install CoworkDesktopInstall) {
	switch install.Trust {
	case CoworkEngineTrusted:
		d.Trusted++
	case CoworkEngineUnsigned:
		d.Unsigned++
	case CoworkEngineNotFound:
		d.NotFound++
	default:
		d.Untrusted++
	}
}

// CoworkAccount is one account's last Cowork event.
type CoworkAccount struct {
	Account     string `json:"account"`
	LastEventAt string `json:"last_event_at,omitempty"`
}

// CoworkAccountEvent is one account's last Cowork hook event in the audit
// store: UserID is the hook row's user.id (a uid or a SID), UserName its
// account name.
type CoworkAccountEvent struct {
	UserID, UserName string
	At               time.Time
}

// CoworkEnrolledAccount is an account the enumerator enrolls.
type CoworkEnrolledAccount struct {
	Account string
	// IDs are the identifiers its hook rows carry (a uid, a SID).
	IDs []string
}

// CoworkInputs are the facts BuildCowork combines.
type CoworkInputs struct {
	Enabled          bool
	MachinePolicy    bool
	HooksInstalled   string
	ManagedHooksOnly string
	Health           []byte
	// DesktopSurfaceRefused: the gateway refuses hook calls from Claude
	// Desktop's surface (connector.SurfaceRefused under unverified_versions:
	// refuse).
	DesktopSurfaceRefused bool
	Enrolled              []CoworkEnrolledAccount
	// Events, EventsTruncated and EventsErr are the audit store lookup;
	// EventsTruncated says it hit its row bound.
	Events          []CoworkAccountEvent
	EventsTruncated bool
	EventsErr       error
}

// BuildCowork is the cowork block.
func BuildCowork(in CoworkInputs) *CoworkState {
	state := &CoworkState{ManagedHooksOnly: oneOf(in.ManagedHooksOnly, "enforce", "preserve")}
	switch {
	case !in.Enabled:
		state.Reason = CoworkReasonConnectorDisabled
	case !in.MachinePolicy || in.HooksInstalled != HooksInstalledAll:
		state.Reason = CoworkReasonMachinePolicyUnset
	case in.DesktopSurfaceRefused:
		state.Reason = CoworkReasonDesktopRefused
	default:
		state.Configured = true
	}
	state.Requests, state.LastEventAt = ParseCoworkHealth(in.Health)
	if in.EventsErr != nil {
		return state
	}
	state.AccountsKnown = true
	state.AccountsTruncated = in.EventsTruncated
	last := map[string]time.Time{}
	byID := map[string]string{}
	for _, account := range in.Enrolled {
		name := strings.TrimSpace(account.Account)
		if name == "" {
			continue
		}
		if _, ok := last[name]; !ok {
			last[name] = time.Time{}
		}
		for _, id := range account.IDs {
			if id = strings.TrimSpace(id); id != "" {
				byID[strings.ToLower(id)] = name
			}
		}
	}
	for _, event := range in.Events {
		name := byID[strings.ToLower(strings.TrimSpace(event.UserID))]
		if name == "" {
			name = strings.TrimSpace(event.UserName)
		}
		if name == "" {
			name = strings.TrimSpace(event.UserID)
		}
		if name == "" || event.At.IsZero() {
			continue
		}
		if event.At.After(last[name]) {
			last[name] = event.At
		}
	}
	names := make([]string, 0, len(last))
	for name := range last {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(state.Accounts) == CoworkAccountsMax {
			state.AccountsTruncated = true
			break
		}
		account := CoworkAccount{Account: name}
		if at := last[name]; !at.IsZero() {
			account.LastEventAt = at.UTC().Format(time.RFC3339)
		}
		state.Accounts = append(state.Accounts, account)
	}
	return state
}

// ParseCoworkHealth reads the claudecode connector's Cowork surface from a
// gateway /health document: its event count and last event time, or zero
// and "" when the gateway has seen none since it started.
func ParseCoworkHealth(body []byte) (requests int64, last string) {
	if len(body) == 0 {
		return 0, ""
	}
	var health struct {
		Connectors []struct {
			Name     string `json:"name"`
			Surfaces map[string]struct {
				Requests       int64      `json:"requests"`
				LastActivityAt *time.Time `json:"last_activity_at"`
			} `json:"surfaces"`
		} `json:"connectors"`
	}
	if json.Unmarshal(body, &health) != nil {
		return 0, ""
	}
	for _, entry := range health.Connectors {
		if !strings.EqualFold(strings.TrimSpace(entry.Name), "claudecode") {
			continue
		}
		cowork, ok := entry.Surfaces["cowork"]
		if !ok || cowork.Requests < 0 {
			return 0, ""
		}
		if cowork.LastActivityAt != nil && !cowork.LastActivityAt.IsZero() {
			last = cowork.LastActivityAt.UTC().Format(time.RFC3339)
		}
		return cowork.Requests, last
	}
	return 0, ""
}

// CoworkLines are the text status lines of the cowork block.
func CoworkLines(state *CoworkState) []string {
	if state == nil {
		return nil
	}
	var line string
	switch {
	case state.Configured:
		line = "cowork: configured (DefenseClaw's Claude Code machine policy hooks are in place)"
	case state.Reason == CoworkReasonConnectorDisabled:
		line = "cowork: not configured (the claudecode connector is not enabled)"
	case state.Reason == CoworkReasonDesktopRefused:
		line = "cowork: not configured (unverified_versions: refuse refuses the Claude Desktop surface Cowork runs on, so Cowork tool calls are refused)"
	default:
		line = "cowork: not configured (DefenseClaw's Claude Code machine policy is not in place)"
	}
	// What the gateway counted comes right after the state, so a
	// configured host with calls says so (cowork-1-0-8 GAP-0032).
	switch {
	case state.Requests > 0 && state.LastEventAt != "":
		line += fmt.Sprintf("; %d hook call(s) reported themselves as Cowork since the gateway started, last %s", state.Requests, state.LastEventAt)
	case state.Requests > 0:
		line += fmt.Sprintf("; %d hook call(s) reported themselves as Cowork since the gateway started", state.Requests)
	default:
		line += "; no hook call has reported itself as Cowork yet (counted since the gateway started)"
	}
	switch state.ManagedHooksOnly {
	case "enforce":
		line += "; managed_hooks_only=enforce (allowManagedHooksOnly: Cowork plugin hooks are meant not to run)"
	case "preserve":
		line += "; managed_hooks_only=preserve (Cowork plugin hooks may run too)"
	}
	lines := append([]string{line}, coworkAccountLines(state)...)
	return append(lines, coworkDesktopLines(state.ClaudeDesktop)...)
}

// coworkAccountLines are the per-account last-event lines of the cowork block.
func coworkAccountLines(state *CoworkState) []string {
	if !state.AccountsKnown {
		return []string{"  cowork per account: unknown (the audit store did not answer)"}
	}
	if len(state.Accounts) == 0 {
		// The store answered with nothing to list: say so, so an empty
		// answer does not read like a block that was cut short.
		return []string{"  cowork per account: none (no enrolled account, and no hook call in the audit store reported itself as Cowork)"}
	}
	var lines []string
	for _, account := range state.Accounts {
		last := account.LastEventAt
		if last == "" {
			last = "never"
		}
		lines = append(lines, "  cowork "+account.Account+": last call reported as Cowork "+last)
	}
	if state.AccountsTruncated {
		lines = append(lines, fmt.Sprintf("  cowork: more accounts than listed (at most %d are shown)", CoworkAccountsMax))
	}
	return lines
}

// coworkDesktopLines are the text lines of the claude_desktop member.
func coworkDesktopLines(desktop *CoworkDesktopState) []string {
	if desktop == nil {
		return nil
	}
	if !desktop.AccountsKnown {
		return []string{"  cowork Claude Desktop per account: unknown (the enumerator's account record could not be read)"}
	}
	if len(desktop.Accounts) == 0 {
		return []string{"  cowork Claude Desktop per account: none (enrollment includes no account yet)"}
	}
	var lines []string
	for _, account := range desktop.Accounts {
		if len(account.Installs) == 0 && account.Reason != "" {
			lines = append(lines, "  cowork "+account.Account+": Claude Desktop not checked ("+account.Reason+")")
			continue
		}
		if len(account.Installs) == 0 {
			lines = append(lines, "  cowork "+account.Account+": no Claude Desktop data folder")
			continue
		}
		for _, install := range account.Installs {
			line := "  cowork " + account.Account + ": Claude Desktop " + install.Deployment + " (" + install.Path + "), "
			if install.Trust == CoworkEngineNotFound {
				line += "no engine build"
			} else {
				line += "engine " + install.EngineVersion + " " + install.Trust
			}
			if install.Reason != "" {
				line += " (" + install.Reason + ")"
			}
			lines = append(lines, line)
		}
		if account.Reason != "" {
			lines = append(lines, "  cowork "+account.Account+": Claude Desktop check incomplete ("+account.Reason+")")
		}
	}
	if desktop.AccountsTruncated {
		lines = append(lines, fmt.Sprintf("  cowork Claude Desktop: more accounts than listed (at most %d are shown)", CoworkAccountsMax))
	}
	return lines
}
