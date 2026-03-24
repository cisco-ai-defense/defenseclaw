package defenseclaw.admission

import rego.v1

# Admission gate: block → allow → scan → severity-based verdict.
# Input fields:
#   target_type  - "skill" or "mcp"
#   target_name  - name of the skill or MCP server
#   path         - filesystem path
#   block_list   - array of {target_type, target_name, reason}
#   allow_list   - array of {target_type, target_name, reason}
#   scan_result  - optional {max_severity, total_findings, findings}
#
# Static data (data.json):
#   config.allow_list_bypass_scan  - bool
#   actions.<SEVERITY>.runtime     - "block" or "allow"
#   severity_ranking.<SEVERITY>    - int (CRITICAL=5 … INFO=1)

default verdict := "scan"

default reason := "awaiting scan"

# --- Block list (highest priority) ---

verdict := "blocked" if _is_blocked

reason := sprintf("%s '%s' is on the block list", [input.target_type, input.target_name]) if {
	verdict == "blocked"
}

# --- Allow list (skip scan when configured) ---

verdict := "allowed" if {
	not _is_blocked
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

# --- Scan: clean (no findings) ---

verdict := "clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}

reason := "scan clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}

# --- Scan: rejected (severity triggers block) ---

verdict := "rejected" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}

reason := sprintf("max severity %s triggers block per policy", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}

# --- Scan: warning (findings present but below block threshold) ---

verdict := "warning" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}

reason := sprintf("findings present (max %s) — allowed with warning", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}

# --- Helper rules ---

_is_blocked if {
	some entry in input.block_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_allow_listed if {
	some entry in input.allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_allow_bypassed if {
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

_has_scan if input.scan_result

_should_reject if {
	data.actions[input.scan_result.max_severity].runtime == "block"
}

# --- Structured output for file action ---

file_action := action if {
	_has_scan
	action := data.actions[input.scan_result.max_severity].file
}

file_action := "none" if {
	not _has_scan
}
