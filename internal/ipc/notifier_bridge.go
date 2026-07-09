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

// composeBody starts from the OS notification body then sweeps once
// more for any secret shape the upstream redactor missed. Each
// pattern replaces its match with `<redacted>` so downstream UIs
// display something meaningful without any risk of leakage. Empty
// bodies keep an empty string — the contract allows optional bodies
// but title is always required by the wire layer.
func composeBody(o notifier.Observation) string {
	body := o.Notification.Body
	if body == "" {
		// The notifier package packs source/severity/connector into
		// Subtitle for the OS toast. For downstream IPC consumers we
		// surface it in the body instead so the context is visible
		// even when the UI does not render subtitles.
		body = o.Notification.Subtitle
	}
	for _, p := range paranoidSecretPatterns {
		body = p.ReplaceAllString(body, "<redacted>")
	}
	return body
}
