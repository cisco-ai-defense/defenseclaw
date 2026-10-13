# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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

default retain_reason := "within retention period"

# High-severity events are always retained regardless of age.
# Use else-chain to avoid conflict when both conditions are true.
retain := true if {
	data.severity_ranking[input.severity] >= data.severity_ranking.HIGH
} else := false if {
	input.age_days > data.audit.retention_days
} else := true

retain_reason := "high severity events are retained indefinitely" if {
	data.severity_ranking[input.severity] >= data.severity_ranking.HIGH
	input.age_days > data.audit.retention_days
}

retain_reason := "exceeded retention period" if {
	input.age_days > data.audit.retention_days
	data.severity_ranking[input.severity] < data.severity_ranking.HIGH
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