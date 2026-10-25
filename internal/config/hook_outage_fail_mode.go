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
// (rpm, pkg, Setup, any managed profile, Secure Client included), savedMode
// the explicit saved mode (or the managed install's resolved mode), and tier
// the connector's policy tier
// (HookPolicyTierForConnector).
//
//   - A managed install keeps savedMode: closed unless its administrator
//     chose open, which outside Secure Client covers a classified outage only.
//     The tier never opens a managed hook.
//   - An explicit saved mode wins on a per-user install too.
//   - A per-user (OSS) install in the strict tier fails closed.
//   - A per-user install in the default (balanced) or permissive tier fails
//     open for an outage: the gateway is not running, has stopped or does not
//     take the call in time. The hook warns, names the fix and records the
//     call in hook-failures.jsonl.
//
// Only an outage can open: an answer the gateway gave (an error status, a
// malformed, partial or oversized answer), a refusal, a missing credential,
// another program on the gateway port and the install window stay closed in
// every tier.
func HookOutageFailMode(managedInstall bool, savedMode, tier string) string {
	if managedInstall {
		return explicitHookFailMode(savedMode)
	}
	if strings.TrimSpace(savedMode) != "" {
		return explicitHookFailMode(savedMode)
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
	return HookOutageFailMode(false, c.configuredHookFailModeForConnector(connector), c.HookPolicyTierForConnector(connector))
}

// HookPolicyTierForConnector is the policy tier of connector's guardrail rule
// pack, as the gateway reads its posture (internal/gateway packPosture): the
// pack manifest's posture, else a built-in pack's own name, else the folder
// name (strict and permissive keep theirs, anything else is default).
func (c *Config) HookPolicyTierForConnector(connector string) string {
	if c == nil {
		return HookPolicyTierDefault
	}
	ref := c.EffectiveRulePackRefForConnector(connector)
	dir := strings.TrimSpace(c.ResolveRulePackDir(ref))
	if dir == "" {
		dir = strings.TrimSpace(ref.Dir)
	}
	if posture := packManifestPosture(dir); posture != "" {
		return posture
	}
	if ref.Name != "" && IsBuiltinRulePack(ref.Name) {
		return ref.Name
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
