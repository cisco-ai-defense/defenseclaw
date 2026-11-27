// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"weak"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Policy tiers of a connector's guardrail rule pack (its posture).
const (
	HookPolicyTierPermissive = "permissive"
	HookPolicyTierDefault    = "default"
	HookPolicyTierStrict     = "strict"
)

// HookOutageFailMode is the one decision of what a hook does while its
// gateway is down (owner decision 2026-10-23, which replaces decision 16 for
// per-user installs). managedInstall is any managed or enterprise install
// (rpm, pkg, Setup, any managed profile, Secure Client included), managedMode
// the mode that install's protected config resolved
// (EffectiveHookFailModeForConnector), and tier the connector's policy tier
// (HookPolicyTierForConnector).
//
//   - A managed install keeps managedMode: closed unless its administrator
//     chose open, which outside Secure Client covers a classified outage only.
//     The tier never opens a managed hook.
//   - A per-user (OSS) install without a saved mode fails closed in the
//     strict tier and opens on a classified outage in the default (balanced)
//     or permissive tier. The hook warns, names the fix and records the call
//     in hook-failures.jsonl.
//
// An explicit saved mode wins over the tier on every install. Only an outage
// can open: an answer the gateway gave (an error status, a malformed, partial
// or oversized answer), an authentication refusal, a missing credential, another program on
// the gateway port and the install window stay closed in every tier.
func HookOutageFailMode(managedInstall bool, managedMode, tier string) string {
	if managedInstall || strings.TrimSpace(managedMode) != "" {
		return explicitHookFailMode(managedMode)
	}
	if normalizeHookPolicyTier(tier) == HookPolicyTierStrict {
		return "closed"
	}
	return "open"
}

// EffectiveHookOutageFailModeForConnector is HookOutageFailMode for this
// config and connector: the mode the connector's hooks are installed with and
// follow while the gateway is down, and the mode status and doctor report.
// Every other hook failure (EffectiveHookFailModeForConnector) stays closed on
// a per-user install.
func (c *Config) EffectiveHookOutageFailModeForConnector(connector string) string {
	return c.EffectiveHookOutageFailModeForConnectorAtTier(connector, c.HookPolicyTierForConnector(connector))
}

// EffectiveHookOutageFailModeForConnectorAtTier uses a tier captured by the
// caller's policy generation instead of rereading a mutable pack manifest.
func (c *Config) EffectiveHookOutageFailModeForConnectorAtTier(connector, tier string) string {
	if c == nil {
		return "closed"
	}
	managedInstall := managed.IsManagedEnterprise(c.DeploymentMode)
	if managedInstall {
		return HookOutageFailMode(true, c.EffectiveHookFailModeForConnector(connector), "")
	}
	// OpenClaw's plugin tool inspection is an in-process check. Its strict
	// policy stays closed even when an older saved hook setting says open.
	if strings.EqualFold(strings.TrimSpace(connector), "openclaw") &&
		normalizeHookPolicyTier(tier) == HookPolicyTierStrict {
		return "closed"
	}
	return HookOutageFailMode(false, c.configuredHookFailModeForConnector(connector), tier)
}

// MCPAdmissionFailsClosed reports whether an MCP server whose install scan
// could not be completed (a launcher or address the scanner refuses, a failed
// scan) is refused for connector: a managed profile and the strict tier fail
// closed. The OSS default (balanced) and permissive tiers keep it available
// with a visible warning, so a server DefenseClaw cannot scan is not treated
// as a malicious one. A completed scan that finds something blocks in every
// profile; this does not decide that. Secure Client keeps its fail-closed
// admission (issue #1092); its callers never reach this.
func (c *Config) MCPAdmissionFailsClosed(connector string) bool {
	return c == nil || managed.IsManagedEnterprise(c.DeploymentMode) ||
		c.HookPolicyTierForConnector(connector) == HookPolicyTierStrict
}

// The ways a user can use an MCP server whose scan cannot run
// (AssetPolicyDecision.ScanNextStep).
const (
	// MCPNextStepAllow: run defenseclaw mcp allow NAME.
	MCPNextStepAllow = "allow"
	// MCPNextStepAdmin: a managed device refuses that command; the
	// administrator allows the server in the managed policy.
	MCPNextStepAdmin = "admin"
	// MCPNextStepList: the name cannot be quoted safely for a command, so
	// defenseclaw mcp list shows the server and its command.
	MCPNextStepList = "list"
)

// MCPAdmissionNextStep is the next step to name for a server called name
// whose scan cannot run. A managed device cannot write an allow rule with the
// CLI, so its user is sent to the administrator; a name that is not plain
// text is not put into a command line.
func (c *Config) MCPAdmissionNextStep(name string) string {
	switch {
	case c != nil && managed.IsManagedEnterprise(c.DeploymentMode):
		return MCPNextStepAdmin
	case MCPNameIsCommandSafe(name):
		return MCPNextStepAllow
	}
	return MCPNextStepList
}

// MCPNameIsCommandSafe reports a server name made only of characters that
// need no shell quoting, the shape an agent-visible command may carry.
func MCPNameIsCommandSafe(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == ':' || r == '@' || r == '/' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// A configuration's first tier resolution is retained while that snapshot
// is in use. Reload creates a new Config, including for an in-place pack edit.
// Weak keys let old snapshots leave with their generations.
var hookPolicyTierSnapshots sync.Map // weak.Pointer[Config] -> *sync.Map

// HookPolicyTierForConnector is the policy tier of connector's guardrail rule
// pack, as the gateway reads its posture (internal/gateway packPosture): the
// generation's pinned manifest posture, else the legacy folder-name table.
// A config-only caller without a loaded generation reads the manifest itself.
// A real built-in selection keeps its tier when no policy directory has been
// resolved; a custom pack may use the same name and takes its own posture.
// A selected custom_packs entry that fails CustomRulePackError is strict.
func (c *Config) HookPolicyTierForConnector(connector string) string {
	if c == nil {
		return HookPolicyTierDefault
	}
	ref := c.EffectiveRulePackRefForConnector(connector)
	if c.brokenCustomRulePackSelected(ref) {
		// A broken custom_packs entry is a config error, whatever its name:
		// the gateway loads its built-in fallback and status names the
		// error, but it is no evidence of a posture that opens an outage.
		return HookPolicyTierStrict
	}
	dir := strings.TrimSpace(c.ResolveRulePackDir(ref))
	if dir == "" {
		dir = strings.TrimSpace(ref.Dir)
	}
	key := weak.Make(c)
	value, loaded := hookPolicyTierSnapshots.Load(key)
	if !loaded {
		value, loaded = hookPolicyTierSnapshots.LoadOrStore(key, new(sync.Map))
		if !loaded {
			runtime.AddCleanup(c, func(key weak.Pointer[Config]) { hookPolicyTierSnapshots.Delete(key) }, key)
		}
	}
	tiers := value.(*sync.Map)
	tierKey := connector + "\x00" + ref.Name + "\x00" + dir
	if tier, ok := tiers.Load(tierKey); ok {
		return tier.(string)
	}
	actual, _ := tiers.LoadOrStore(tierKey, c.resolveHookPolicyTier(ref, dir))
	return actual.(string)
}

// resolveHookPolicyTier reads the tier of the rule pack ref names in dir: the
// generation's pinned posture, a custom pack the config-load check accepted,
// the pack's own tier (manifest, else tiers.yaml), a built-in name, then the
// legacy strict folder (packFolderPosture).
func (c *Config) resolveHookPolicyTier(ref RulePackRef, dir string) string {
	if posture, pinned := c.PinnedRulePackPosture(dir); pinned {
		if posture != "" {
			return normalizeHookPolicyTier(posture)
		}
		return packFolderPosture(dir)
	}
	if custom, selected := c.UsableCustomRulePack(ref.Name); selected {
		// A standalone hook has no rule generation. Its posture comes from
		// the one config-load verdict: a pack the rule loader accepted whose
		// files hash to the selected pin. A binary without the loader cannot
		// prove a pinned pack, so its posture never sets an outage tier.
		checked, _ := c.customRulePackCheck(ref.Name)
		if checked.validated {
			if checked.posture != "" {
				return checked.posture
			}
			return packFolderPosture(dir)
		}
		if strings.TrimSpace(custom.Digest) != "" {
			return HookPolicyTierStrict
		}
	}
	if posture := packOwnPosture(dir); posture != "" {
		return posture
	}
	if dir == "" && IsBuiltinRulePack(ref.Name) {
		if _, custom := c.Guardrail.CustomPacks[ref.Name]; !custom {
			return ref.Name
		}
	}
	return packFolderPosture(dir)
}

// packManifestPosture is the posture defenseclaw-pack.json in dir names, ""
// when it names none (no dir, no manifest, an unreadable or oversized one).
func packManifestPosture(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, "defenseclaw-pack.json"))
	if err != nil || len(raw) > 1<<20 {
		return ""
	}
	var manifest struct {
		Posture string `json:"posture"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return ""
	}
	switch posture := strings.ToLower(strings.TrimSpace(manifest.Posture)); posture {
	case HookPolicyTierDefault, HookPolicyTierStrict, HookPolicyTierPermissive:
		return posture
	}
	return ""
}

// packOwnPosture is the pack's own tier in dir: its manifest posture, else
// the tier field of its tiers.yaml (guardrail.ReadPackPosture reads the same
// two), "" when neither names one. The tiers.yaml is read as the loader reads
// it (decide.ParseColumn: known fields, version, rows): a file the loader
// refuses names no tier, so the caller falls back to the built-in name or
// the folder, never to a tier from a file no generation would load (DET111
// T19 review P3-3).
func packOwnPosture(dir string) string {
	if posture := packManifestPosture(dir); posture != "" {
		return posture
	}
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tiers.yaml"))
	if err != nil || len(raw) > 1<<20 {
		return ""
	}
	column, err := decide.ParseColumn(raw)
	if err != nil {
		return ""
	}
	switch tier := column.Tier.String(); tier {
	case HookPolicyTierDefault, HookPolicyTierStrict, HookPolicyTierPermissive:
		return tier
	}
	return ""
}

// packFolderPosture is the tier of a pack that names none of its own (no
// manifest posture, no tiers.yaml): a legacy copy in a folder named strict
// keeps strict, which a 1.0.10 install of it had (owner ruling on
// rel-1-0-10:GAP-1562: never weaker by a missing field); every other folder
// is default. A folder name never lowers a tier: a manifest-less folder named
// permissive is default (a pack's tier comes from its own tier field).
func packFolderPosture(dir string) string {
	if strings.TrimSpace(dir) != "" && strings.EqualFold(filepath.Base(filepath.Clean(dir)), HookPolicyTierStrict) {
		return HookPolicyTierStrict
	}
	return HookPolicyTierDefault
}

func normalizeHookPolicyTier(tier string) string {
	switch t := strings.ToLower(strings.TrimSpace(tier)); t {
	case HookPolicyTierStrict, HookPolicyTierPermissive:
		return t
	}
	return HookPolicyTierDefault
}
