package defenseclaw.audit

import rego.v1

# Evaluates audit event retention and export rules.
# Input fields:
#   event_type     - "scan", "admission", "enforcement", etc.
#   severity       - "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
#   age_days       - how old the event is in days
#   export_targets - available export destinations (e.g. ["splunk"])
#
# Static data (data.json):
#   audit.retention_days     - max retention period
#   audit.log_all_actions    - whether to log everything
#   audit.log_scan_results   - whether to log scan results
#   severity_ranking         - severity → int ranking

default retain := true

default retain_reason := "within retention period"

# Expire events older than the retention period.
retain := false if {
	input.age_days > data.audit.retention_days
}

retain_reason := "exceeded retention period" if {
	input.age_days > data.audit.retention_days
}

# Always retain high-severity events regardless of age.
retain := true if {
	data.severity_ranking[input.severity] >= data.severity_ranking.HIGH
}

retain_reason := "high severity events are retained indefinitely" if {
	input.age_days > data.audit.retention_days
	data.severity_ranking[input.severity] >= data.severity_ranking.HIGH
}

# Export to all available targets when severity is HIGH or above.
export_to contains target if {
	data.severity_ranking[input.severity] >= data.severity_ranking.HIGH
	some target in input.export_targets
}

# Export scan results when configured.
export_to contains target if {
	input.event_type == "scan"
	data.audit.log_scan_results == true
	some target in input.export_targets
}
