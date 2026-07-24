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

// aidCategoryPhrases maps AID SCREAMING_SNAKE_CASE classification
// tokens to user-facing lower-case phrases for the managed_enterprise
// notification body. AVC's UI shows the title alone in the pop-up and
// title+body concatenated in message history, so the body needs to
// read naturally to an end user.
//
// Any token not present here falls through to a mechanical
// lower-case-with-spaces transform via humanizeAIDCategory. That
// keeps a newly-added AID category rendering reasonably in the field
// (e.g. "NEW_CATEGORY_X" → "new category x") without a DefenseClaw
// release; adding an entry here is a copy-quality improvement, not a
// correctness bar.
var aidCategoryPhrases = map[string]string{
	"SECURITY_VIOLATION":    "security violation",
	"PRIVACY_VIOLATION":     "privacy violation",
	"SAFETY_VIOLATION":      "safety violation",
	"PROMPT_INJECTION":      "prompt injection",
	"NONE_ATTACK_TECHNIQUE": "policy violation",
	"LOW_SEVERITY":          "low-severity policy signal",
}

// newObserver returns a notifier.Observer that maps each observation
// to a NotificationRecord and hands it to bcast.publish. Registered
// with dispatcher.AddObserver from the sidecar wiring layer.
//
// managedEnterprise switches on the two-surface AVC copy contract:
// title alone in the pop-up, title+body concatenated in message
// history. Under that mode we use per-category composers that
// produce end-user copy ("The request was blocked for security
// violation and the following signals: Prompt Injection"). Outside
// managed_enterprise the observer keeps the historical
// composeTitle/composeBody flow that shares strings with the OS
// toast surface (see internal/gateway/notifier for the OS side).
//
// Mapping rules — see plan §6:
//
//	OnBlock           → ERROR   / TRANSIENT_AND_HISTORY
//	OnWouldBlock      → WARNING / TRANSIENT_AND_HISTORY  ("would ask" for WouldAsk)
//	OnApprovalPending → WARNING / TRANSIENT              (approval prompts are ephemeral)
//	OnServiceState    → WARNING / TRANSIENT              (gateway up/down)
func newObserver(bcast *broadcast, managedEnterprise bool) notifier.Observer {
	return func(o notifier.Observation) {
		rec := recordFromObservation(o, managedEnterprise)
		if rec == nil {
			return
		}
		bcast.publish(rec)
	}
}

func recordFromObservation(o notifier.Observation, managedEnterprise bool) *pb.NotificationRecord {
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

	var title, body string
	if managedEnterprise {
		title, body = composeManaged(o)
	} else {
		title = composeTitle(o)
		body = composeBody(o)
	}
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
// system tray. Used only outside managed_enterprise.
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
// optional bodies but title is always required. Used only outside
// managed_enterprise; the managed path composes bespoke text per
// category via composeManaged.
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
	body = redactSecretsInBody(body)
	return body
}

// composeManaged produces the (title, body) pair sent to AVC on
// managed_enterprise hosts. AVC's UI shows the title alone in the
// pop-up surface and title+body concatenated inline in the message
// history, so the copy is intentionally split: the title says WHAT
// happened, the body says WHY.
//
// The four dispatcher categories (Block, WouldBlock, Approval,
// ServiceState — see internal/gateway/notifier.Category) each get a
// bespoke template. Extra structure needed by a template (BlockEvent
// findings, ApprovalEvent subject, ServiceStateEvent state) is
// pulled from o.Event via a type switch; when the payload is absent
// or of an unexpected type, the composer falls back to safe generic
// copy rather than empty strings.
//
// The paranoid-secret sweep still runs on every returned body so
// this managed-mode copy path is subject to the same "no
// credentials in a body" invariant as composeBody above.
func composeManaged(o notifier.Observation) (string, string) {
	var title, body string
	switch o.Category {
	case notifier.CategoryBlock:
		title, body = composeBlockManaged(o)
	case notifier.CategoryWouldBlock:
		title, body = composeWouldBlockManaged(o)
	case notifier.CategoryApproval:
		title, body = composeApprovalManaged(o)
	case notifier.CategoryServiceState:
		title, body = composeServiceStateManaged(o)
	default:
		// Unknown category — recordFromObservation already returns
		// nil above, so this is unreachable. Kept defensive so a
		// future category addition still yields non-empty text.
		title = "DefenseClaw notification"
	}
	if strings.TrimSpace(title) == "" {
		title = "DefenseClaw notification"
	}
	body = redactSecretsInBody(body)
	return title, body
}

// composeBlockManaged renders the Block category on managed_enterprise.
//
//	Title: "DefenseClaw blocked the request"
//	Body:  "The request was blocked for <categories> and the following
//	        signals: <signals>"
//
// <categories> is derived from the AID SCREAMING_SNAKE_CASE tokens
// parsed out of BlockEvent.Reason. When no AID tokens are present
// (asset-policy block, hook guardian, blocklist deny) the categories
// fall back to "a policy violation" so the body still reads
// naturally. When no signals are present the "signals" clause is
// dropped entirely.
func composeBlockManaged(o notifier.Observation) (string, string) {
	cats, sigs := parseAIDReason(reasonForParse(o))
	return "DefenseClaw blocked the request",
		blockLikeBody("The request was blocked for", cats, sigs, "")
}

// composeWouldBlockManaged renders the WouldBlock category — either
// observe-mode "would have blocked" or "would have asked about"
// (BlockEvent.WouldAsk true when a confirm verdict couldn't reach
// the chat surface — see notifier.BlockEvent godoc). The body
// always ends with a parenthetical clarifying observe-mode
// semantics so users understand there was no enforcement.
func composeWouldBlockManaged(o notifier.Observation) (string, string) {
	verb := "blocked"
	titleVerb := "have blocked"
	if ev, ok := o.Event.(notifier.BlockEvent); ok && ev.WouldAsk {
		verb = "asked about"
		titleVerb = "have asked about"
	}
	title := "DefenseClaw would " + titleVerb + " the request"
	cats, sigs := parseAIDReason(reasonForParse(o))
	body := blockLikeBody(
		"The request would have been "+verb+" for",
		cats, sigs,
		" (observe mode: no enforcement taken)",
	)
	return title, body
}

// composeApprovalManaged renders the Approval (HITL / confirm)
// category. Approval prompts always require a user action — the
// title tells them to look, the body tells them what and why.
func composeApprovalManaged(o notifier.Observation) (string, string) {
	subject := "an agent action"
	reason := "policy review"
	if ev, ok := o.Event.(notifier.ApprovalEvent); ok {
		if s := strings.TrimSpace(ev.Subject); s != "" {
			subject = s
		}
		if r := strings.TrimSpace(ev.Reason); r != "" {
			reason = r
		}
	}
	title := "DefenseClaw needs your approval"
	body := "Reply in your chat to approve or deny: " + subject + " flagged for " + reason
	return title, body
}

// composeServiceStateManaged renders the ServiceState category.
// The existing notifier.serviceStateNotification titles ("DefenseClaw
// protection paused" / "DefenseClaw protection restored") already
// meet the short-self-contained-title bar, so the managed path
// keeps them verbatim and only reshapes the body.
func composeServiceStateManaged(o notifier.Observation) (string, string) {
	title := strings.TrimSpace(o.Notification.Title)
	if title == "" {
		title = "DefenseClaw protection state changed"
	}
	body := ""
	if ev, ok := o.Event.(notifier.ServiceStateEvent); ok {
		if r := strings.TrimSpace(ev.Reason); r != "" {
			body = "Reason: " + r
		}
	}
	// Fall back to the notification's own body when the typed
	// payload didn't carry a reason (dev / test paths sometimes
	// dispatch service-state without a full event).
	if body == "" {
		if b := strings.TrimSpace(o.Notification.Body); b != "" {
			body = "Reason: " + b
		}
	}
	return title, body
}

// blockLikeBody assembles the "The request was blocked for X and
// the following signals: Y" body shape shared by Block and WouldBlock
// composers. The trailer is appended verbatim (e.g. observe-mode
// tail); the categories block always renders, the signals block is
// omitted when sigs is empty.
func blockLikeBody(prefix string, cats, sigs []string, trailer string) string {
	catPhrase := "a policy violation"
	if len(cats) > 0 {
		humans := make([]string, 0, len(cats))
		for _, c := range cats {
			humans = append(humans, humanizeAIDCategory(c))
		}
		catPhrase = humanCategoryList(humans)
	}
	body := prefix + " " + catPhrase
	if len(sigs) > 0 {
		body += " and the following signals: " + strings.Join(sigs, ", ")
	}
	body += trailer
	return body
}

// reasonForParse returns the RICHEST available body string for the
// managed-mode composer to hand to parseAIDReason. Prefers the typed
// event's Reason field (BlockEvent.Reason / ApprovalEvent.Reason)
// which is UNTRUNCATED, and falls back to o.Notification.Body which
// the notifier package pre-truncates to 140 chars via truncateReason
// for OS-toast readability.
//
// The truncation cap on the toast is deliberate — a macOS Notification
// Center toast cannot render more than a few lines cleanly. But AVC's
// Message History surface renders the wire body inline with far more
// room, and truncation there lost the tail of long violation lists
// like "Violence & Public Safety Threats" (visible as "Safety Th..."
// before this fix). Feeding the untruncated Reason into parseAIDReason
// closes that gap without changing the OS-toast body path.
//
// For CategoryApproval the ApprovalEvent.Reason isn't AID-shaped, but
// keeping the same helper shape avoids caller-side type-switch churn;
// parseAIDReason returns ([], []) on any non-AID prefix and every
// caller already handles that case.
func reasonForParse(o notifier.Observation) string {
	switch ev := o.Event.(type) {
	case notifier.BlockEvent:
		if r := strings.TrimSpace(ev.Reason); r != "" {
			return r
		}
	case notifier.ApprovalEvent:
		if r := strings.TrimSpace(ev.Reason); r != "" {
			return r
		}
	}
	return o.Notification.Body
}

// parseAIDReason splits a "Cisco AI Defense: <mixed>" body into its
// category tokens (SCREAMING_SNAKE_CASE — SECURITY_VIOLATION,
// PRIVACY_VIOLATION, ...) and its signal tokens (rule names like
// "Prompt Injection", "PII"). The split reuses the same regexes that
// compactAIDCategories keys on so the two paths stay in lockstep.
// Body strings that don't match the AID prefix return
// ([], []) — the caller falls back to generic copy.
func parseAIDReason(body string) (categories []string, signals []string) {
	m := ciscoAIDefenseBodyPrefix.FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	tail := strings.TrimSpace(m[1])
	if tail == "" {
		return nil, nil
	}
	for _, p := range strings.Split(tail, ",") {
		token := strings.TrimSpace(p)
		if token == "" {
			continue
		}
		if categoryTokenPattern.MatchString(token) {
			categories = append(categories, token)
		} else {
			signals = append(signals, token)
		}
	}
	return categories, signals
}

// humanizeAIDCategory turns an AID SCREAMING_SNAKE_CASE token into a
// user-facing lower-case phrase. Uses the aidCategoryPhrases map
// when available; falls back to a mechanical lower-case + replace-
// underscore-with-space transform so a newly-added AID token still
// renders reasonably ("NEW_CATEGORY_X" → "new category x") without
// a DefenseClaw release.
func humanizeAIDCategory(token string) string {
	if phrase, ok := aidCategoryPhrases[token]; ok {
		return phrase
	}
	return strings.ToLower(strings.ReplaceAll(token, "_", " "))
}

// humanCategoryList joins a list of already-humanized category
// phrases into English-style prose. Empty → "a policy violation"
// (defensive; callers guard len(cats)==0 above). One → verbatim.
// Two → "A and B" (no Oxford comma for two items). Three-plus →
// "A, B, and C" (Oxford comma).
func humanCategoryList(cats []string) string {
	switch len(cats) {
	case 0:
		return "a policy violation"
	case 1:
		return cats[0]
	case 2:
		return cats[0] + " and " + cats[1]
	default:
		return strings.Join(cats[:len(cats)-1], ", ") + ", and " + cats[len(cats)-1]
	}
}

// redactSecretsInBody applies the paranoid secret sweep from
// paranoidSecretPatterns to a composed body. Extracted so the
// managed and unmanaged composers both go through one choke point.
func redactSecretsInBody(body string) string {
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
//
// Only used on the unmanaged path — managed_enterprise callers
// compose their own body per category via composeManaged.
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
