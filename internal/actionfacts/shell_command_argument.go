// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "encoding/json"

// ShellCommandArgument is the command text of shell arguments under any key
// the trusted-action parser reads as the command (canonicalInputFieldName:
// command, cmd, script, CommandLine, ...). Keys that disagree name no
// command (ok false): the gateway's conflicting-keys check judges that call.
//
// The gateway's Windows dialect selection and hook-config guard read the
// command through it, and so does the hook client for a shell tool whose
// command is under neither command nor cmd: agy run_command
// ({"CommandLine": ...}) was offered no PowerShell reading on a Windows host
// (rel-1-0-10:GAP-0784), and its writes were listed for no managed gateway
// (rel-1-0-10:GAP-1132).
func ShellCommandArgument(raw json.RawMessage) (string, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return "", false
	}
	command, found := "", false
	for key, value := range object {
		if field, _ := canonicalInputFieldName(key); field != "command" {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || (found && text != command) {
			return "", false
		}
		command, found = text, true
	}
	return command, found
}
