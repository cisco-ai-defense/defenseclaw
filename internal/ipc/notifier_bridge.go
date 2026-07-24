// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// ciscoAIDefenseCategoryOnlyPattern matches the "Cisco AI Defense:
// <finding>[, <finding>...]" body that normalizeCiscoResponse
// produces for block / would-block events. The list mixes two shapes:
//   - Category labels (SCREAMING_SNAKE_CASE from the AID
//     classification enum): SECURITY_VIOLATION, PRIVACY_VIOLATION,
//     SAFETY_VIOLATION, PROMPT_INJECTION, ...
//   - Individual rule names (Title Case): "Prompt Injection", "PII",
//     "Malicious URL Detection", ...
//
// SecureClient's notification toast only has room for the high-level
// category summary — the per-rule detail comes through the audit
// event, not the toast. Strip the rule-name entries here so
// downstream toast rendering shows a clean category-only line.
//
// The regex captures the "Cisco AI Defense:" prefix so we can rewrite
// only that specific body shape and leave anything else (asset-policy
// blocks, connector-native errors, service-state events) untouched.
var ciscoAIDefenseBodyPrefix = regexp.MustCompile(`^Cisco AI Defense:\s*(.*)$`)

// categoryTokenPattern is the "keep" filter applied to each
// comma-separated element of the AID findings list. Category labels
// are SCREAMING_SNAKE_CASE enum values that always contain at least
// one underscore: SECURITY_VIOLATION, PRIVACY_VIOLATION,
// SAFETY_VIOLATION, NONE_ATTACK_TECHNIQUE, LOW_SEVERITY, ...
//
// Rule-name entries fall into two shapes and both must be excluded:
//   - Title Case with spaces: "Prompt Injection", "Malicious URL Detection"
//   - Uppercase acronyms without underscores: PII, PHI, PCI, ABA, ITIN
//
// The underscore requirement lets us keep every real AID category
// while dropping every rule-name shape. Any lowercase letter or
// space is also disqualifying.
var categoryTokenPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`)

// paranoidSecretPatterns is a last-line defense against notifier call
// sites leaking a secret into the notification body. The upstream
// redactor should have handled everything, but the wire contract is
// explicit about "no secrets, credentials, tokens, raw prompts, raw
// policy bodies, or sensitive payloads" so we sweep once more before
// publish. Each pattern is a bounded-length regex to keep matching
// cheap on truncated bodies.
//
// Coverage:
//   - HTTP auth headers: `Bearer <token>`, `Authorization: Basic <b64>`.
//   - Key/value shapes: api_key, api-key, apikey, password, token,
//     secret, passwd, passphrase (case-insensitive, `=` or `:` separator).
//   - AWS-style access key ids: AKIA + 16 base32 chars.
//   - JWT-shaped strings: three dot-separated base64url segments.
//   - PEM private-key blocks (any line that opens one).
var paranoidSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{4,}`),
	regexp.MustCompile(`(?i)authorization\s*:\s*(?:basic|bearer|digest)\s+[A-Za-z0-9._~+/=-]{4,}`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|password|passwd|passphrase|secret)\s*[:=]\s*\S+`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

// newObserver returns a notifier.Observer that maps each observation
// to a NotificationRecord and hands it to bcast.publish. Registered
// with dispatcher.AddObserver from the sidecar wiring layer.
//
// Mapping rules — see plan §6:
//
//	OnBlock           → ERROR   / TRANSIENT_AND_HISTORY
//	OnWouldBlock      → WARNING / TRANSIENT_AND_HISTORY  ("would ask" for WouldAsk)
//	OnApprovalPending → WARNING / TRANSIENT              (approval prompts are ephemeral)
//	OnServiceState    → WARNING / TRANSIENT              (gateway up/down)
func newObserver(bcast *broadcast) notifier.Observer {
	return func(o notifier.Observation) {
		rec := recordFromObservation(o)
		if rec == nil {
			return
		}
		bcast.publish(rec)
	}
}

func recordFromObservation(o notifier.Observation) *pb.NotificationRecord {
	var (
		severity     pb.NotificationSeverity
		presentation pb.NotificationPresentation
	)
	switch o.Category {
	case notifier.CategoryBlock:
		severity = pb.NotificationSeverity_NOTIFICATION_SEVERITY_ERROR
		presentation = pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY
	case notifier.CategoryWouldBlock:
		severity = pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING
		presentation = pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY
	case notifier.CategoryApproval:
		severity = pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING
		presentation = pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT
	case notifier.CategoryServiceState:
		severity = pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING
		presentation = pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT
	default:
		return nil
	}

	title := composeTitle(o)
	body := composeBody(o)
	return &pb.NotificationRecord{
		SchemaVersion: schemaVersion,
		Severity:      severity,
		Presentation:  presentation,
		Title:         title,
		Body:          body,
	}
}

// composeTitle prefers the OS toast's title field (which the notifier
// package already renders consistently for each category) so the
// wire notification matches what an operator would see in the
// system tray.
func composeTitle(o notifier.Observation) string {
	if t := strings.TrimSpace(o.Notification.Title); t != "" {
		return t
	}
	return "DefenseClaw notification"
}

// composeBody starts from the OS notification body then:
//
//  1. If the body is the "Cisco AI Defense: <mixed>" shape, drops
//     every non-category token so SecureClient's toast surface only
//     shows the high-level classification labels. Per-rule signals
//     ("Prompt Injection", "PII", "Malicious URL Detection", ...)
//     still land in the audit trail but are omitted from the toast
//     text where they overflow the display.
//  2. Sweeps for any secret shape the upstream redactor missed and
//     replaces it with `<redacted>`.
//
// Empty bodies keep an empty string — the wire contract allows
// optional bodies but title is always required.
func composeBody(o notifier.Observation) string {
	body := o.Notification.Body
	if body == "" {
		// The notifier package packs source/severity/connector into
		// Subtitle for the OS toast. For downstream IPC consumers we
		// surface it in the body instead so the context is visible
		// even when the UI does not render subtitles.
		body = o.Notification.Subtitle
	}
	body = compactAIDCategories(body)
	for _, p := range paranoidSecretPatterns {
		body = p.ReplaceAllString(body, "<redacted>")
	}
	return body
}

// compactAIDCategories rewrites a body of the form
//
//	Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, Prompt Injection, PII
//
// down to just the SCREAMING_SNAKE_CASE category tokens:
//
//	Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION
//
// Any body that doesn't start with the "Cisco AI Defense:" prefix
// passes through unchanged — asset-policy blocks, connector-native
// errors, service-state events, and hook-guardian notifications all
// have their own body shapes and shouldn't be touched here.
//
// If filtering leaves zero category tokens (e.g. AID returned only
// rule-name findings), the original body is preserved so the toast
// still carries some usable text — an empty "Cisco AI Defense:"
// with nothing after would be worse than the mixed version.
func compactAIDCategories(body string) string {
	m := ciscoAIDefenseBodyPrefix.FindStringSubmatch(body)
	if m == nil {
		return body
	}
	tail := m[1]
	if strings.TrimSpace(tail) == "" {
		return body
	}
	parts := strings.Split(tail, ",")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		token := strings.TrimSpace(p)
		if token == "" {
			continue
		}
		if categoryTokenPattern.MatchString(token) {
			kept = append(kept, token)
		}
	}
	if len(kept) == 0 {
		return body
	}
	return "Cisco AI Defense: " + strings.Join(kept, ", ")
}
