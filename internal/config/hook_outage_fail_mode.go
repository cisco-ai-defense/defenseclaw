// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

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
		c.HookPolicyTierForConnector(connector) == HookPolicyTierStrict {
		return "closed"
	}
	return HookOutageFailMode(false, c.configuredHookFailModeForConnector(connector), c.HookPolicyTierForConnector(connector))
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
	if posture := packManifestPosture(dir); posture != "" {
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

// packFolderPosture is the folder-name posture table: strict and permissive
// keep their names, every other folder (and none) is default.
func packFolderPosture(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return HookPolicyTierDefault
	}
	switch base := strings.ToLower(filepath.Base(filepath.Clean(dir))); base {
	case HookPolicyTierStrict, HookPolicyTierPermissive:
		return base
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
