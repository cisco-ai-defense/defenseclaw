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
	return HookOutageFailMode(false, c.configuredHookFailModeForConnector(connector), tier)
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
// the pack manifest, a built-in name, then the folder-name table.
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
