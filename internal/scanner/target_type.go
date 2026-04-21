// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

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
