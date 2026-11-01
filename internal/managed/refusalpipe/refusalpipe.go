// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package refusalpipe carries the refusal reports of the Windows standalone
// hook to the managed gateway.
//
// A call from an account the administrator excludes or has not enrolled yet
// is refused by the hook itself: the account has no runtime, so it holds no
// gateway credential, and the refusal left no audit row (GAP-1242). The hook
// reports each refusal on a named pipe the gateway service owns. The gateway
// takes the caller's SID from the pipe client's token
// (ImpersonateNamedPipeClient at identification level), never from the
// message; the message carries only an allowlisted connector and reason and
// bounded event and tool labels. The gateway coalesces reports per SID and
// connector, so a refusal loop cannot flood the audit log.
//
// The managed CLI reports its refusals of a standard account's command the
// same way (GAP-2639): such an account holds no gateway credential either. A
// command report carries only the refused command's fixed words and a reason,
// never its arguments, and becomes the refused-command row the Unix gateway
// writes for its hook socket's peer (managed_refusal_audit.go).
package refusalpipe

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// PipeName is the gateway service pipe for refusal reports.
const PipeName = `\\.\pipe\` + managed.StandaloneWindowsGatewaySvc + `-unenrolled-refusals`

// MaxMessageBytes bounds one report.
const MaxMessageBytes = 1024

// The refusal reasons a report may carry: the Windows standalone hook's
// unenrolled-account refusals (enterprisehooks.WindowsManagedSIDUnregisteredReason
// and enterprisehooks.WindowsManagedEnrollmentPendingReason).
const (
	ReasonSIDUnregistered   = "enterprise_managed_sid_unregistered"
	ReasonEnrollmentPending = "enterprise_managed_enrollment_pending"
	// ReasonManagedDevice and ReasonElevationRequired are the reasons of a
	// command report: a write the managed device takes only from the admin
	// config, and a lifecycle command a standard account may not run.
	ReasonManagedDevice     = "managed_device"
	ReasonElevationRequired = "elevation_required"
)

// maxCommandBytes and maxCommandWords bound a command report's words.
const (
	maxCommandBytes = 64
	maxCommandWords = 4
)

// connectors are the Windows managed hook connectors
// (enterprisehooks.ResolveWindowsManagedHookRuntime).
var connectors = map[string]bool{
	"claudecode": true, "codex": true, "cursor": true, "copilot": true, "antigravity": true,
	"devin": true, "hermes": true, "kiro": true, "opencode": true,
}

// Report is one refused hook call or CLI command.
type Report struct {
	Connector string `json:"connector"`
	Reason    string `json:"reason"`
	// Event and Tool are what the agent sent. The account is not trusted,
	// so they only label the row.
	Event string `json:"event,omitempty"`
	Tool  string `json:"tool,omitempty"`
	// Command is a CLI command report's words, such as "guardrail disable";
	// such a report has no connector, event or tool.
	Command string `json:"command,omitempty"`
}

// Normalize returns the report with bounded labels, or false when its
// connector or reason is not one a refusal can have.
func (r Report) Normalize() (Report, bool) {
	if r.Command != "" {
		command, ok := commandWords(r.Command)
		reason := strings.TrimSpace(r.Reason)
		if !ok || strings.TrimSpace(r.Connector) != "" || r.Event != "" || r.Tool != "" ||
			(reason != ReasonManagedDevice && reason != ReasonElevationRequired) {
			return Report{}, false
		}
		return Report{Command: command, Reason: reason}, true
	}
	r.Connector = strings.ToLower(strings.TrimSpace(r.Connector))
	r.Reason = strings.TrimSpace(r.Reason)
	if !connectors[r.Connector] || (r.Reason != ReasonSIDUnregistered && r.Reason != ReasonEnrollmentPending) {
		return Report{}, false
	}
	r.Event = label(r.Event, 64)
	r.Tool = label(r.Tool, 128)
	return r, true
}

// label keeps a short identifier-like value and drops anything else.
// commandWords accepts a command's fixed words only: up to maxCommandWords
// words of lower-case letters, digits and dashes, so no argument (a path, a
// value, a key=value) can reach the audit row.
func commandWords(command string) (string, bool) {
	words := strings.Fields(command)
	if len(words) == 0 || len(words) > maxCommandWords {
		return "", false
	}
	for _, word := range words {
		for _, c := range word {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	joined := strings.Join(words, " ")
	return joined, len(joined) <= maxCommandBytes
}

func label(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return ""
	}
	for _, c := range value {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.' || c == ':' || c == '/':
		default:
			return ""
		}
	}
	return value
}

// Encode returns the wire form of a report.
func Encode(r Report) ([]byte, error) {
	normalized, ok := r.Normalize()
	if !ok {
		return nil, errors.New("refusal report has no supported connector or command and reason")
	}
	return json.Marshal(normalized)
}

// Decode parses and normalizes one report message.
func Decode(message []byte) (Report, error) {
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return Report{}, errors.New("refusal report size is out of bounds")
	}
	var r Report
	if err := json.Unmarshal(message, &r); err != nil {
		return Report{}, errors.New("refusal report is not valid JSON")
	}
	normalized, ok := r.Normalize()
	if !ok {
		return Report{}, errors.New("refusal report has no supported connector or command and reason")
	}
	return normalized, nil
}

// AccountSID reports whether sid names a user account a refusal can be
// attributed to: a local or domain account (S-1-5-21-) or a Microsoft Entra
// account (S-1-12-1-). Service, system and other well-known SIDs are not.
func AccountSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}
