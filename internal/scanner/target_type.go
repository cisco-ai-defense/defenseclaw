// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// InferTargetType maps scanner name to a coarse target_type for observability.
func InferTargetType(scannerName string) string {
	switch scannerName {
	case "mcp-scanner", "mcp_scanner":
		return "mcp"
	case "skill-scanner", "skill_scanner":
		return "skill"
	case "plugin-scanner", "plugin_scanner", "defenseclaw-plugin-scanner":
		return "plugin"
	case "aibom", "aibom-claw":
		return "inventory"
	case "codeguard",
		"clawshield-vuln", "clawshield-secrets", "clawshield-pii",
		"clawshield-malware", "clawshield-injection":
		return "code"
	default:
		return "unknown"
	}
}

// NormalizeScannerEnum maps a raw scanner name to the v7 gateway-event
// schema enum ("skill" | "mcp" | "plugin" | "aibom" | "codeguard").
// ClawShield family scanners are treated as codeguard siblings since
// they ship builtin code/content detectors. Unknown scanners fall
// back to "codeguard" (the most generic, always-schema-valid option)
// rather than an empty string so that downstream SIEM pivots keep
// working and we never drop a scan event for scanner-name-only
// schema violations. Callers should prefer passing the Scanner()
// Name() of the scanner struct.
func NormalizeScannerEnum(scannerName string) string {
	switch strings.TrimSpace(scannerName) {
	case "skill", "skill-scanner", "skill_scanner":
		return "skill"
	case "mcp", "mcp-scanner", "mcp_scanner":
		return "mcp"
	case "plugin", "plugin-scanner", "plugin_scanner", "defenseclaw-plugin-scanner":
		return "plugin"
	case "aibom", "aibom-claw":
		return "aibom"
	case "codeguard",
		"clawshield-vuln", "clawshield-secrets", "clawshield-pii",
		"clawshield-malware", "clawshield-injection":
		return "codeguard"
	default:
		return "codeguard"
	}
}

// NormalizeTargetTypeEnum maps a raw target_type to the v7
// gateway-event schema enum ("file" | "skill" | "mcp" | "plugin"
// | "aibom"). Unknown / empty values are coerced to "file" (the
// generic filesystem-object bucket) because the schema only allows
// the listed enum values or nil, and we want to keep the payload
// valid without hand-wiring every scanner. Callers should still
// set TargetType on ScanResult when they have a better-typed value.
func NormalizeTargetTypeEnum(targetType string) string {
	switch strings.TrimSpace(targetType) {
	case "file", "skill", "mcp", "plugin", "aibom":
		return targetType
	case "inventory":
		return "aibom"
	case "code", "", "unknown":
		return "file"
	default:
		return "file"
	}
}

// NormalizeVerdictEnum maps a raw verdict value to the v7
// gateway-event schema enum ("clean" | "warn" | "block"). Unknown
// values (including upper-case variants produced by external
// scanners) are mapped to their case-insensitive equivalent, and
// anything else falls back to "clean" rather than an empty string
// so the event stays schema-valid.
func NormalizeVerdictEnum(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "clean", "pass", "ok", "success":
		return "clean"
	case "warn", "warning", "medium", "low":
		return "warn"
	case "block", "fail", "critical", "high", "reject":
		return "block"
	default:
		return "clean"
	}
}
