package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type fallbackAction struct {
	Runtime string `json:"runtime"`
	File    string `json:"file"`
	Install string `json:"install"`
}

type firstPartyEntry struct {
	Reason             string
	SourcePathContains []string
}

type FallbackProfile struct {
	AllowListBypassScan bool
	ScanOnInstall       bool
	Actions             map[string]fallbackAction
	ScannerOverrides    map[string]map[string]fallbackAction
	FirstPartyAllow     map[string]firstPartyEntry
}

func LoadFallbackProfile(regoDir string) *FallbackProfile {
	profile := &FallbackProfile{
		AllowListBypassScan: true,
		ScanOnInstall:       true,
		Actions: map[string]fallbackAction{
			"CRITICAL": {Runtime: "block", File: "quarantine", Install: "block"},
			"HIGH":     {Runtime: "block", File: "quarantine", Install: "block"},
			"MEDIUM":   {Runtime: "allow", File: "none", Install: "none"},
			"LOW":      {Runtime: "allow", File: "none", Install: "none"},
			"INFO":     {Runtime: "allow", File: "none", Install: "none"},
		},
		ScannerOverrides: map[string]map[string]fallbackAction{},
		FirstPartyAllow:  map[string]firstPartyEntry{},
	}
	if regoDir == "" {
		return profile
	}

	raw, err := readDataJSON(regoDir)
	if err != nil {
		return profile
	}

	var payload struct {
		Config struct {
			AllowListBypassScan *bool `json:"allow_list_bypass_scan"`
			ScanOnInstall       *bool `json:"scan_on_install"`
		} `json:"config"`
		Actions          map[string]fallbackAction            `json:"actions"`
		ScannerOverrides map[string]map[string]fallbackAction `json:"scanner_overrides"`
		FirstPartyAllow []struct {
			TargetType         string   `json:"target_type"`
			TargetName         string   `json:"target_name"`
			Reason             string   `json:"reason"`
			SourcePathContains []string `json:"source_path_contains"`
		} `json:"first_party_allow_list"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return profile
	}

	if payload.Config.AllowListBypassScan != nil {
		profile.AllowListBypassScan = *payload.Config.AllowListBypassScan
	}
	if payload.Config.ScanOnInstall != nil {
		profile.ScanOnInstall = *payload.Config.ScanOnInstall
	}
	for sev, action := range payload.Actions {
		profile.Actions[strings.ToUpper(sev)] = action
	}
	for targetType, overrides := range payload.ScannerOverrides {
		target := map[string]fallbackAction{}
		for sev, action := range overrides {
			target[strings.ToUpper(sev)] = action
		}
		profile.ScannerOverrides[targetType] = target
	}
	for _, entry := range payload.FirstPartyAllow {
		if entry.TargetType == "" || entry.TargetName == "" {
			continue
		}
		profile.FirstPartyAllow[firstPartyKey(entry.TargetType, entry.TargetName)] = firstPartyEntry{
			Reason:             entry.Reason,
			SourcePathContains: entry.SourcePathContains,
		}
	}
	return profile
}

func EvaluateAdmissionFallback(input AdmissionInput, profile *FallbackProfile) *AdmissionOutput {
	if profile == nil {
		profile = LoadFallbackProfile("")
	}

	if blocked, reason := fallbackListEntryReason(input.BlockList, input.TargetType, input.TargetName); blocked {
		return &AdmissionOutput{Verdict: "blocked", Reason: reason}
	}
	if allowed, reason := fallbackListEntryReason(input.AllowList, input.TargetType, input.TargetName); allowed {
		return &AdmissionOutput{Verdict: "allowed", Reason: reason}
	}

	if profile.AllowListBypassScan {
		if entry, ok := profile.FirstPartyAllow[firstPartyKey(input.TargetType, input.TargetName)]; ok {
			if matchesProvenance(entry.SourcePathContains, input.Path) {
				reason := entry.Reason
				if reason == "" {
					reason = fmt.Sprintf("%s '%s' is on the allow list — scan skipped", input.TargetType, input.TargetName)
				}
				return &AdmissionOutput{Verdict: "allowed", Reason: reason}
			}
		}
	}

	if input.ScanResult == nil {
		if !profile.ScanOnInstall {
			return &AdmissionOutput{
				Verdict: "allowed",
				Reason:  "scan_on_install disabled — allowed without scan",
			}
		}
		return &AdmissionOutput{Verdict: "scan", Reason: "scan required"}
	}

	severity := strings.ToUpper(input.ScanResult.MaxSeverity)
	if severity == "" {
		severity = "INFO"
	}
	action := effectiveFallbackAction(profile, input.TargetType, severity)
	out := &AdmissionOutput{
		FileAction:    coalesceAction(action.File, "none"),
		InstallAction: coalesceAction(action.Install, "none"),
		RuntimeAction: coalesceAction(action.Runtime, "allow"),
	}

	if input.ScanResult.TotalFindings <= 0 {
		out.Verdict = "clean"
		out.Reason = "scan clean"
		return out
	}

	if action.Runtime == "block" || action.Install == "block" {
		out.Verdict = "rejected"
		out.Reason = fmt.Sprintf("max severity %s triggers block per policy", severity)
		return out
	}

	out.Verdict = "warning"
	out.Reason = fmt.Sprintf("findings present (max %s) — allowed with warning", severity)
	return out
}

func effectiveFallbackAction(profile *FallbackProfile, targetType, severity string) fallbackAction {
	if profile == nil {
		return fallbackAction{}
	}
	if overrides, ok := profile.ScannerOverrides[targetType]; ok {
		if action, ok := overrides[strings.ToUpper(severity)]; ok {
			return action
		}
	}
	if action, ok := profile.Actions[strings.ToUpper(severity)]; ok {
		return action
	}
	return fallbackAction{}
}

func firstPartyKey(targetType, targetName string) string {
	return targetType + "\x00" + targetName
}

func coalesceAction(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// matchesProvenance returns true when no provenance constraints exist or
// when at least one constraint substring is found in the normalised path.
func matchesProvenance(constraints []string, path string) bool {
	if len(constraints) == 0 {
		return true
	}
	if path == "" {
		return false
	}
	normalised := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, c := range constraints {
		if strings.Contains(normalised, strings.ToLower(c)) {
			return true
		}
	}
	return false
}

// readDataJSON tries <dir>/rego/data.json first, then <dir>/data.json.
// The rego/ subdirectory is where _seed_rego_policies writes the active
// policy and is the canonical location. The root fallback covers the case
// where the caller already points directly at the rego/ directory.
func readDataJSON(dir string) ([]byte, error) {
	regoPath := filepath.Join(dir, "rego", "data.json")
	raw, err := os.ReadFile(regoPath)
	if err == nil {
		return raw, nil
	}
	return os.ReadFile(filepath.Join(dir, "data.json"))
}

func fallbackListEntryReason(entries []ListEntry, targetType, targetName string) (bool, string) {
	for _, entry := range entries {
		if entry.TargetType == targetType && entry.TargetName == targetName {
			if entry.Reason != "" {
				return true, entry.Reason
			}
			return true, fmt.Sprintf("%s '%s' is on the allow/block list", targetType, targetName)
		}
	}
	return false, ""
}
