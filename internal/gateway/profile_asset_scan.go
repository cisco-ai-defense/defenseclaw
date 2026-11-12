// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// profileAssetScanApplies says whether this gateway judges the skill and
// plugin text the hook sends instead of a folder it reads: a managed Windows
// gateway (LocalSystem) reads nothing in a user profile, so an enrolled
// account's skill or plugin never reached an install scan, and a skill
// created while the gateway was stopped was never caught up (GAP-0699,
// GAP-0701). Tests replace it to run on any OS.
var profileAssetScanApplies = watcherUsesEnrolledUserDirs

// profileAssetVerdict is the outcome of scanning one folder's text.
type profileAssetVerdict struct {
	Blocking bool
	Severity string
	Rules    []string
}

// profileAssetRefusedRules are the detector rules that refuse a profile asset
// at the hook: text that overrides the agent's role or instructions, frames
// itself as a system message, or hides one in base64 or in tag characters.
// The detector's other HIGH findings (a zero-width character, which a byte
// order mark or an emoji sequence holds, and mixed scripts, which any
// multilingual text holds) are common in ordinary skills and do not refuse
// one.
var profileAssetRefusedRules = map[string]bool{
	"CS-INJ-role_override": true, "CS-INJ-instruction_injection": true, "CS-INJ-delimiter_injection": true,
	"CS-INJ-base64_injection": true, "CS-INJ-unicode_tags": true,
}

// maxProfileAssetVerdicts bounds the verdicts kept by content digest.
const maxProfileAssetVerdicts = 256

var profileAssetVerdicts = struct {
	sync.Mutex
	byDigest map[string]profileAssetVerdict
}{byDigest: map[string]profileAssetVerdict{}}

// scanProfileAssetContent scans the files of content with the in-process
// prompt-injection detector and keeps the verdict by the digest of the text,
// so an unchanged folder is scanned once.
func scanProfileAssetContent(content assetfacts.Content) profileAssetVerdict {
	profileAssetVerdicts.Lock()
	verdict, ok := profileAssetVerdicts.byDigest[content.Digest]
	profileAssetVerdicts.Unlock()
	if ok {
		return verdict
	}
	for _, file := range content.Files {
		for _, finding := range scanner.ScanTextContent([]byte(file.Text), file.Rel) {
			if !profileAssetRefusedRules[finding.ID] ||
				(finding.Severity != scanner.SeverityHigh && finding.Severity != scanner.SeverityCritical) {
				continue
			}
			verdict.Blocking = true
			if verdict.Severity != string(scanner.SeverityCritical) {
				verdict.Severity = string(finding.Severity)
			}
			if rule := strings.TrimSpace(finding.ID); rule != "" && !slices.Contains(verdict.Rules, rule) {
				verdict.Rules = append(verdict.Rules, rule)
			}
		}
	}
	profileAssetVerdicts.Lock()
	if len(profileAssetVerdicts.byDigest) >= maxProfileAssetVerdicts {
		clear(profileAssetVerdicts.byDigest)
	}
	profileAssetVerdicts.byDigest[content.Digest] = verdict
	profileAssetVerdicts.Unlock()
	return verdict
}

// profileAssetContentDecision refuses a skill or plugin of an enrolled
// account whose text the hook read and the detector rates HIGH or CRITICAL,
// and a skill or plugin the hook found but sent no text for, or sent only
// part of (an old hook, or one that could not read all of the folder, must
// not skip the scan). It applies on a managed
// Windows gateway when asset_policy is enabled in action mode with runtime
// detection on for the asset type, and then whatever the guardrail mode says;
// the default configuration, observe mode, other gateways and Secure Client
// are unchanged (#1092). The text is the hook's claim.
func (a *APIServer) profileAssetContentDecision(
	ctx context.Context, cfg *config.Config, connector, targetType, runtimeSurface string, probe skillRuntimeProbe,
) (config.AssetPolicyDecision, bool) {
	if cfg == nil || probe.RuntimeDisableOnly || !profileAssetScanApplies(cfg) || cfg.SecureClientIntegration() ||
		!cfg.AssetPolicy.Enabled || !assetRuntimeModeIsAction(cfg.EffectiveAssetPolicyModeForConnector(connector)) {
		return config.AssetPolicyDecision{}, false
	}
	if detection, _ := cfg.AssetRuntimeDetectionFor(targetType); !detection.Enabled {
		return config.AssetPolicyDecision{}, false
	}
	if _, serviceAccount := callerHomeForAssets(ctx); !serviceAccount {
		return config.AssetPolicyDecision{}, false
	}
	name := strings.TrimSpace(probe.SkillName)
	facts := claimedAssetFactsFromContext(ctx)
	contents := facts.ContentsFor(targetType, name)
	// A Claude Code skill spelled plugin:skill is a skill of that plugin, and
	// the hook sends the plugin folder; one with no folder sent was not found.
	pluginOfSkill := ""
	if plugin, _, qualified := strings.Cut(name, ":"); qualified && targetType == "skill" && connector == "claudecode" && plugin != "" {
		pluginOfSkill = plugin
		contents = append(contents, facts.ContentsFor("plugin", plugin)...)
	}
	refuse := func(reason, source string) (config.AssetPolicyDecision, bool) {
		decision := runtimeAssetDisableBlockDecision(targetType, name, connector, runtimeSurface, reason, source)
		decision.RegistryStatus = "unknown"
		return decision, true
	}
	for _, content := range contents {
		if content.Truncated {
			// The hook could not read all of it (a file past the bounds, a link
			// that leads nowhere readable, text that is not UTF-8): a verdict on
			// the part it sent is not a verdict on the asset.
			return refuse(fmt.Sprintf("%s %q holds content DefenseClaw could not read in full; asset_policy runtime detection refuses an asset it cannot scan", targetType, name),
				"profile-asset-unscanned")
		}
		if verdict := scanProfileAssetContent(content); verdict.Blocking {
			return refuse(fmt.Sprintf("%s %q holds content rated %s (%s); asset_policy runtime detection refuses it",
				targetType, name, verdict.Severity, strings.Join(verdict.Rules, ", ")), "profile-asset-verdict")
		}
	}
	if pluginOfSkill != "" && len(contents) == 0 {
		return refuse(fmt.Sprintf("skill %q belongs to plugin %q in the account's profile and its content was not sent for scanning; asset_policy runtime detection refuses an unscanned plugin skill", name, pluginOfSkill),
			"profile-asset-unscanned")
	}
	if targetType == "plugin" && len(contents) == 0 && connector == "claudecode" && name != "" && !strings.EqualFold(name, "unknown") &&
		probe.ToolName != coworkPluginInstallTool {
		// The hook reads every Claude Code plugin a request names; a named
		// plugin with no content is one it could not find or read (or an old
		// hook), and so one nothing has scanned.
		return refuse(fmt.Sprintf("plugin %q is in the account's profile and its content was not sent for scanning; asset_policy runtime detection refuses an unscanned plugin", name),
			"profile-asset-unscanned")
	}
	if targetType == "skill" {
		for _, dir := range facts.SkillDirs {
			if config.SameAssetName(filepath.Base(dir), name) && !slices.ContainsFunc(contents, func(c assetfacts.Content) bool { return sameCleanPath(c.Dir, dir) }) {
				return refuse(fmt.Sprintf("skill %q is in the account's profile and its content was not sent for scanning; asset_policy runtime detection refuses an unscanned skill", name),
					"profile-asset-unscanned")
			}
		}
	}
	return config.AssetPolicyDecision{}, false
}
