// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// extractExactPersistenceArgs exposes only the executable portion of the
// observed persist(method,payload) contract. The adapter is deliberately
// closed: payload classes that are data rather than commands (for example SSH
// keys and PAM modules) never enter the command parser.
func extractExactPersistenceArgs(raw json.RawMessage) extractedInput {
	if len(bytes.TrimSpace(raw)) == 0 {
		return extractedInput{status: StatusNotApplicable}
	}
	if len(raw) > maxArgsJSONBytes {
		return extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueInputLimit}}
	}
	if !utf8.Valid(raw) {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidUTF8}}
	}
	if issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue != "" {
		status := StatusInvalid
		if issue == IssueDuplicateJSONKey {
			status = StatusAmbiguous
		} else if issue == IssueInputLimit || issue == IssueDepthLimit {
			status = StatusLimitExceeded
		}
		return extractedInput{status: status, issues: []IssueCode{issue}}
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 2 {
		return persistenceInputPartial()
	}
	method, methodOK := object["method"].(string)
	payload, payloadOK := object["payload"].(string)
	if !methodOK || !payloadOK || method == "" || strings.TrimSpace(method) != method ||
		payload == "" || strings.TrimSpace(payload) == "" {
		return persistenceInputPartial()
	}
	for key := range object {
		if key != "method" && key != "payload" {
			return persistenceInputPartial()
		}
	}

	var command string
	var ok bool
	switch method {
	case "cron":
		command, ok = exactPersistenceCronCommand(payload)
	case "systemd":
		command, ok = exactPersistenceSystemdCommand(payload)
	case "scheduled_task", "registry_run", "wmi_subscription":
		command, ok = payload, true
	default:
		return persistenceInputPartial()
	}
	if !ok {
		return persistenceInputPartial()
	}
	if issue := validateCommandText(command); issue != "" {
		return extractedInput{status: statusForInputIssue(issue), issues: []IssueCode{issue}}
	}
	return extractedInput{command: command, status: StatusComplete}
}

func persistenceInputPartial() extractedInput {
	return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
}

func exactPersistenceCronCommand(payload string) (string, bool) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n") {
		return "", false
	}
	fields := strings.Fields(trimmed)
	if len(fields) >= 2 && strings.HasPrefix(fields[0], "@") {
		if !exactPersistenceCronAlias(fields[0]) {
			return "", false
		}
		return strings.TrimSpace(strings.TrimPrefix(trimmed, fields[0])), true
	}
	if len(fields) >= 6 && exactPersistenceCronSchedule(fields[:5]) {
		prefix := strings.Join(fields[:5], " ")
		command := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		if strings.HasPrefix(command, "root ") {
			command = strings.TrimSpace(strings.TrimPrefix(command, "root"))
		}
		return command, command != ""
	}
	// Some persist tools accept the schedule separately and expose only the
	// command in payload. Keep that exact, non-empty command form supported.
	return trimmed, true
}

func exactPersistenceCronAlias(value string) bool {
	switch value {
	case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
		return true
	default:
		return false
	}
}

func exactPersistenceCronSchedule(fields []string) bool {
	if len(fields) != 5 {
		return false
	}
	for _, field := range fields {
		if field == "" || len(field) > 128 || strings.ContainsAny(field, "`$'\"\\<>{}[]") {
			return false
		}
		for _, character := range field {
			if (character < '0' || character > '9') && character != '*' &&
				character != '/' && character != ',' && character != '-' {
				return false
			}
		}
	}
	return true
}

func exactPersistenceSystemdCommand(payload string) (string, bool) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return "", false
	}
	if !strings.Contains(trimmed, "\n") && !strings.HasPrefix(trimmed, "ExecStart=") {
		return trimmed, true
	}
	var command string
	for _, line := range strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		candidate := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		if candidate == "" || command != "" {
			return "", false
		}
		command = candidate
	}
	return command, command != ""
}
