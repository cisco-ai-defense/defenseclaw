package defenseclaw.skill_actions

import rego.v1

# Maps a severity level to runtime and file actions using data.actions.
# Input fields:
#   severity - "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO"
#
# Static data (data.json):
#   actions.<SEVERITY>.runtime - "block" or "allow"
#   actions.<SEVERITY>.file    - "quarantine" or "none"

default runtime_action := "allow"

default file_action := "none"

runtime_action := action if {
	action := data.actions[input.severity].runtime
}

file_action := action if {
	action := data.actions[input.severity].file
}

should_block if {
	runtime_action == "block"
}

should_quarantine if {
	file_action == "quarantine"
}
