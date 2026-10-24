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
// gateway is down. managedInstall is any managed or enterprise install
// (rpm, pkg, Setup, any managed profile, Secure Client included), and
// managedMode is the mode that install's protected config resolved.
//
//   - A managed install keeps managedMode: closed unless its administrator
//     chose open, which outside Secure Client covers a classified outage only.
//   - A per-user (OSS) install fails closed in every policy tier.
//
// Only an outage can open: an answer the gateway gave (an error status, a
// malformed, partial or oversized answer), a refusal, a missing credential,
// another program on the gateway port and the install window stay closed in
// every tier. A configured per-user guardrail.hook_fail_mode does not change
// the per-user answer.
func HookOutageFailMode(managedInstall bool, managedMode string) string {
	if managedInstall {
		return explicitHookFailMode(managedMode)
	}
	return "closed"
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
		return HookOutageFailMode(true, c.EffectiveHookFailModeForConnector(connector))
	}
	return HookOutageFailMode(false, "")
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
