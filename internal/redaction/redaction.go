// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redaction provides PII-safe rendering of strings, evidence
// windows, verdict reasons, and message bodies for use in logs and
// telemetry.
//
// # Threat model
//
// DefenseClaw inspects LLM traffic that routinely contains personally
// identifiable information (phone numbers, SSNs, credentials, customer
// records). Operators need rich diagnostic detail to triage false
// positives and security incidents, but raw PII must never be the
// default in any sink — including stderr, SQLite, Splunk HEC, or OTel
// log exporters.
//
// # Reveal flag
//
// The DEFENSECLAW_REVEAL_PII environment variable, when set to a truthy
// value, makes operator-facing log writers emit the original content
// in place of redacted placeholders. This is intended for short-lived
// incident triage on a workstation; it MUST NOT be set on servers in
// steady state. The flag affects ONLY stderr (and therefore the daemon
// gateway.log + TUI Logs panel). Persistent sinks — SQLite audit
// store, Splunk HEC, OTel log exporters, webhook payloads — never
// honor the flag and always emit the redacted form. This isolation is
// enforced by routing those sinks through ForSink* helpers below
// rather than the raw Reveal-respecting variants.
//
// These helpers are the immutable v7 compatibility projection. They do not
// consult v8 configuration and they have no process-global bypass. The v8
// runtime retains raw source facts until routing, then applies the selected
// redaction profile independently for each destination.
//
// # Output format
//
// Redactions follow a single, parseable shape:
//
//	<redacted len=N sha=8hex>
//
// The 8-char hex prefix of SHA-256(value) lets operators correlate the
// same value across log lines without exposing the value itself. The
// length is preserved so false-positive triage (e.g. distinguishing a
// 9-digit value from a 16-digit value) still works.
package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

// revealEnvVar is the single environment variable that opts logs into
// emitting raw values in place of redacted placeholders. Kept as an
// unexported constant so callers cannot accidentally introduce parallel
// flags that defeat the audit story.
const revealEnvVar = "DEFENSECLAW_REVEAL_PII"

// disableEnvVar is retained for the non-canonical compatibility surfaces that
// still honor the pre-v8 process-wide opt-out. Canonical v8 telemetry never
// consults it: the runtime retains source facts and applies a compiled profile
// independently for each destination.
const disableEnvVar = "DEFENSECLAW_DISABLE_REDACTION"

var disableOverride atomic.Bool

// SetDisableAll updates the legacy compatibility override. It must not be used
// to select a canonical v8 destination profile.
func SetDisableAll(v bool) { disableOverride.Store(v) }

func DisableAll() bool {
	if disableOverride.Load() {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(disableEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// agentReasonRedactionDisabled is the managed-enterprise, local-agent-only
// carve-out. It never changes canonical persistence or destination routing.
var agentReasonRedactionDisabled atomic.Bool

func SetAgentReasonRedactionDisabled(v bool) { agentReasonRedactionDisabled.Store(v) }

// hashPrefixHex is the number of leading hex characters of SHA-256
// preserved in the placeholder. 8 hex chars (32 bits) is enough to
// correlate distinct values within a single incident window without
// being a meaningful preimage hint.
const hashPrefixHex = 8

// shortValueByteThreshold is the byte length below which we omit the
// hash prefix entirely. Tiny values (1-4 bytes) hash uniquely enough
// that even a truncated SHA gives a meaningful hint, and they are
// nearly always non-PII metadata anyway (status codes, "ok", etc.).
const shortValueByteThreshold = 5

// entityPrefixRevealMinBytes is the byte length at or above which
// ForSinkEntity emits the leading rune as a preview. Keeping the
// threshold at 10 means 6- to 9-byte secrets (short phone extensions,
// truncated SSN fragments) don't leak their first character.
const entityPrefixRevealMinBytes = 10

// compactRuleIDMaxBytes is the maximum length of a "rule-ID-shaped"
// token that contains no recognizable separator (`-`, `.`, `:`,
// `/`, `_`). Real rule identifiers in the catalog are either short
// all-caps words (UNKNOWN, ERROR, HIGH — all ≤11 bytes) or longer
// tokens with separators (SEC-ANTHROPIC, PII-SSN-US, CODEGUARD-0-XSS).
// Bare alphanumeric tokens longer than this are almost certainly
// secrets or user-supplied data (AWS AKIA* access keys, bare
// passphrases) and must be redacted.
const compactRuleIDMaxBytes = 11

// Reveal reports whether operator-facing log writers should emit raw
// values in place of redacted placeholders. Defaults to false.
//
// The flag is read fresh on every call so tests can flip it via
// t.Setenv without process restart. The cost (one syscall + a string
// compare) is negligible on the logging hot path because Reveal is
// only consulted inside the redaction helpers, which themselves are
// only called when something is actually about to be logged.
func Reveal() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(revealEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// String redacts an arbitrary string for safe logging. When Reveal()
// is true the original is returned unchanged; otherwise the standard
// "<redacted len=N sha=...>" placeholder is returned.
func String(s string) string {
	if Reveal() {
		return s
	}
	return ForSinkString(s)
}

// ForSinkString is the Reveal-bypassing compatibility projection. It honors
// the pre-v8 DisableAll opt-out; new v8 producers must retain the raw fact and
// let the central destination projection apply policy.
//
// Idempotent: a value already shaped like a redaction placeholder is
// returned unchanged so layered helpers don't lose the original hash
// or length on a second pass.
func ForSinkString(s string) string {
	if DisableAll() {
		return s
	}
	return LegacyV7String(s)
}

// redactString is the unconditional compatibility core used when a
// per-inspection Cisco AI Defense directive forces redaction.
func redactString(s string) string { return LegacyV7String(s) }

// LegacyV7String applies the exact v7 arbitrary-string projection without
// consulting environment variables or mutable package state. It exists only
// for the immutable observability-v8 legacy-v7 migration profile; new policy
// code should use the central v8 projection engine instead.
func LegacyV7String(s string) string {
	if s == "" {
		return "<empty>"
	}
	if isPlaceholder(s) {
		return s
	}
	n := len(s)
	if n < shortValueByteThreshold {
		return fmt.Sprintf("<redacted len=%d>", n)
	}
	return fmt.Sprintf("<redacted len=%d sha=%s>", n, hashPrefix(s))
}

// Strict placeholder grammar. Only strings produced by our own
// formatters above are recognized as already-redacted; anything that
// merely starts with `<redacted` and ends with `>` is treated as raw
// attacker-controlled data and re-redacted on the next sink pass.
//
// The four exact shapes (anchored, no whitespace tolerance):
//
//	<empty>
//	<redacted len=N>
//	<redacted len=N sha=8hex>
//	<redacted len=N prefix="X" sha=8hex>           (entity rune preview)
//	<redacted-evidence len=N sha=8hex>
//	<redacted-evidence len=N match=[A:B] sha=8hex> (evidence)
//
// `prefix=%q` escapes the inner rune via Go's strconv quoting, so
// the inner field can contain Go escape sequences like `\u00e9`,
// `\xff`, `\\`, `\"`. We cap the inner field at 16 bytes so
// pathological prefix values cannot inflate the placeholder past
// the documented bound.
var (
	placeholderShortRe    = regexp.MustCompile(`^<redacted len=\d{1,12}>$`)
	placeholderStandardRe = regexp.MustCompile(`^<redacted len=\d{1,12} sha=[0-9a-f]{8}>$`)
	placeholderEntityRe   = regexp.MustCompile(`^<redacted len=\d{1,12} prefix="(?:[^"\\]|\\.){1,16}" sha=[0-9a-f]{8}>$`)
	placeholderEvidenceRe = regexp.MustCompile(`^<redacted-evidence len=\d{1,12}(?: match=\[\d{1,12}:\d{1,12}\])? sha=[0-9a-f]{8}>$`)
)

// isPlaceholder reports whether s is one of our own redaction
// placeholder shapes. Used to make the ForSink* helpers idempotent.
//
// The recognizer is grammar-anchored: a string like
// `<redacted sk-ant-secret>` or `<redacted alice@example.com>` looks
// vaguely placeholder-shaped but does NOT match any of the four
// strict shapes above, so it is correctly treated as raw data and
// redacted again at every sink boundary.
func isPlaceholder(s string) bool {
	if s == "<empty>" {
		return true
	}
	if !strings.HasPrefix(s, "<redacted") || !strings.HasSuffix(s, ">") {
		return false
	}
	if len(s) > 96 {
		return false
	}
	if strings.ContainsAny(s, "\n\r\t") {
		return false
	}
	switch {
	case strings.HasPrefix(s, "<redacted-evidence"):
		return placeholderEvidenceRe.MatchString(s)
	case placeholderEntityRe.MatchString(s):
		return true
	case placeholderStandardRe.MatchString(s):
		return true
	case placeholderShortRe.MatchString(s):
		return true
	}
	return false
}

// isEvidencePlaceholder reports whether s is the strict evidence
// placeholder shape. ForSinkEvidence uses this for idempotency
// instead of a loose prefix/suffix check so that an attacker-supplied
// `<redacted-evidence sk-secret>` is re-redacted instead of preserved.
func isEvidencePlaceholder(s string) bool {
	if len(s) > 96 || strings.ContainsAny(s, "\n\r\t") {
		return false
	}
	return placeholderEvidenceRe.MatchString(s)
}

// Entity redacts a PII entity (phone, SSN, email, token, etc.)
// preserving length and — for values long enough that one rune of
// hint cannot be a preimage — the first rune.
func Entity(value string) string {
	if Reveal() {
		return value
	}
	return ForSinkEntity(value)
}

// ForSinkEntity is the Reveal-bypassing compatibility projection. It is
// idempotent over its own placeholder shape and honors DisableAll.
//
// The first-rune preview is only included for values long enough
// that a single character cannot be a meaningful fraction of the
// secret (≥ entityPrefixRevealMinBytes). Short values fall back to
// the plain length+hash placeholder because, e.g., leaking the
// leading `A` of a 6-byte value like `AB4FGH` narrows the search
// space for an attacker who controls adjacent log rows.
func ForSinkEntity(value string) string {
	if DisableAll() {
		return value
	}
	return LegacyV7Entity(value)
}

func redactEntity(value string) string { return LegacyV7Entity(value) }

// LegacyV7Entity applies the exact v7 entity projection without consulting
// environment variables or mutable package state. The reviewed byte-length
// threshold and first-rune preview are preserved for migration compatibility.
func LegacyV7Entity(value string) string {
	if value == "" {
		return "<empty>"
	}
	if isPlaceholder(value) {
		return value
	}
	n := len(value)
	if n < shortValueByteThreshold {
		return fmt.Sprintf("<redacted len=%d>", n)
	}
	if n < entityPrefixRevealMinBytes {
		return fmt.Sprintf("<redacted len=%d sha=%s>", n, hashPrefix(value))
	}
	r, size := utf8.DecodeRuneInString(value)
	if r == utf8.RuneError && size <= 1 {
		return fmt.Sprintf("<redacted len=%d sha=%s>", n, hashPrefix(value))
	}
	return fmt.Sprintf("<redacted len=%d prefix=%q sha=%s>", n, string(r), hashPrefix(value))
}

// MessageContent redacts an LLM message body or request payload —
// typically multi-paragraph user content. Output omits any character
// preview entirely (length + hash only) because previews of LLM
// content are the single largest historical PII leak source.
func MessageContent(content string) string {
	if Reveal() {
		return content
	}
	return ForSinkMessageContent(content)
}

// ForSinkMessageContent is the Reveal-bypassing compatibility projection.
// It is idempotent, ignores Reveal, and honors DisableAll.
func ForSinkMessageContent(content string) string {
	if DisableAll() {
		return content
	}
	return LegacyV7MessageContent(content)
}

func redactMessageContent(content string) string { return LegacyV7MessageContent(content) }

// LegacyV7MessageContent applies the exact v7 model/tool-content projection
// without consulting environment variables or mutable package state.
func LegacyV7MessageContent(content string) string {
	if content == "" {
		return "<empty>"
	}
	if isPlaceholder(content) {
		return content
	}
	return fmt.Sprintf("<redacted len=%d sha=%s>", len(content), hashPrefix(content))
}

// Reason redacts a verdict reason string. Reasons are typically built
// by the guardrail engine in the form
//
//	"<rule-id>: matched <literal>; <rule-id>: ..."
//
// We keep the rule-id tokens (which are hand-authored and PII-free
// by construction) and redact the literal portions.
func Reason(reason string) string {
	if Reveal() {
		return reason
	}
	return ForSinkReason(reason)
}

// ForSinkReason is the Reveal-bypassing legacy-v7 projection. It always
// redacts free-form values regardless of the display-only Reveal flag.
//
// Idempotent: if the input has already been through redaction (i.e.
// contains "<redacted" markers and no other content), it is returned
// unchanged.
func ReasonForAgent(reason string) string {
	if agentReasonRedactionDisabled.Load() {
		return reason
	}
	return ForSinkReason(reason)
}

func ForSinkReason(reason string) string {
	if DisableAll() {
		return reason
	}
	return LegacyV7Reason(reason)
}

func redactReason(reason string) string { return LegacyV7Reason(reason) }

// LegacyV7Reason applies the exact v7 bounded token-aware reason projection
// without consulting environment variables or mutable package state.
func LegacyV7Reason(reason string) string {
	if reason == "" {
		return ""
	}
	if isAlreadyRedacted(reason) {
		return reason
	}
	// Trusted whole-reason allow-list: the AID normalizer at
	// internal/gateway/cisco_inspect.go emits ship-authored strings
	// of the shape "Cisco AI Defense: <rule>[, <rule>...]" (comma-
	// joined rule catalog names). Those clauses are NOT user content
	// — they're DefenseClaw-authored labels — so we let the whole
	// reason pass through unredacted rather than fragmenting on ", "
	// (which drops the trusted-prefix context and redacts the
	// individual rule names). See trustedReasonPassthrough for the
	// narrow validation.
	if r := trustedReasonPassthrough(reason); r != "" {
		return r
	}
	out := strings.Builder{}
	out.Grow(len(reason))
	emit := func(t string) {
		out.WriteString(redactReasonToken(t))
	}
	start := 0
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		if (c == ';' || c == ',') && i+1 < len(reason) && reason[i+1] == ' ' {
			emit(reason[start:i])
			out.WriteByte(c)
			out.WriteByte(' ')
			i++
			start = i + 1
		}
	}
	emit(reason[start:])
	return out.String()
}

// isAlreadyRedacted reports whether s is the output of a previous
// redaction pass. Only strings that consist entirely of
// "<redacted...>" placeholders and the safe glue tokens are
// considered redacted.
func isAlreadyRedacted(s string) bool {
	if !strings.Contains(s, "<redacted") {
		return false
	}
	rest := s
	for rest != "" {
		for len(rest) >= 2 && (rest[0] == ';' || rest[0] == ',') && rest[1] == ' ' {
			rest = rest[2:]
		}
		next := len(rest)
		for i := 0; i+1 < len(rest); i++ {
			if (rest[i] == ';' || rest[i] == ',') && rest[i+1] == ' ' {
				next = i
				break
			}
		}
		tok := strings.TrimSpace(rest[:next])
		if tok == "" {
			rest = rest[next:]
			continue
		}
		if !isRedactedToken(tok) && !isSafeReasonToken(tok) {
			return false
		}
		if next == len(rest) {
			break
		}
		rest = rest[next:]
	}
	return true
}

// isRedactedToken reports whether tok is one of our placeholder
// shapes or a "key: <redacted...>" pair. Uses the strict
// isPlaceholder grammar so a spoofed `<redacted alice@example.com>`
// or `rule: <redacted secret>` token is NOT treated as already-safe
// during the idempotency check on incoming reasons.
func isRedactedToken(tok string) bool {
	if isPlaceholder(tok) {
		return true
	}
	if idx := strings.Index(tok, ": "); idx > 0 {
		prefix := tok[:idx]
		rest := tok[idx+2:]
		if isRuleIDChars(prefix) && isPlaceholder(rest) {
			return true
		}
	}
	return false
}

// redactReasonToken applies the per-clause redaction policy.
//
// Recognized shapes in priority order:
//
//  1. "<rule-id>: <description>"     — space-delimited; keep ID and
//     recurse into the description so nested rule-id:literal shapes
//     (e.g. `matched: SEC-AWS-KEY:AWS access key`) preserve the
//     inner rule ID while still scrubbing any literals
//  2. "<rule-id>:<description>"      — colon-delimited (our standard finding
//     format, e.g. "SEC-ANTHROPIC:API key ...") — keep ID,
//     redact the description wholesale because it is free-form
//     text that routinely embeds the offending literal
//  3. "<key>=<value>" (no whitespace) — classic audit key=value
//  4. Multi-pair whitespace clause   — delegated to redactWhitespaceTokens
//  5. Plain safe reason token        — rule-id characters only
//  6. Fallback                       — whole-token redaction
func redactReasonToken(t string) string {
	return redactReasonTokenDepth(t, 0)
}

// trustedReasonPassthrough returns the input unchanged when it matches
// one of the ship-authored trusted reason shapes. Returns "" when the
// input doesn't match, deferring to the normal redaction rules.
func trustedReasonPassthrough(t string) string {
	const aidPrefix = "Cisco AI Defense"
	if !strings.HasPrefix(t, aidPrefix) {
		return ""
	}
	// Exact "Cisco AI Defense custom policy block" catch-all reason
	// emitted when the cloud blocks without naming a specific rule.
	if t == "Cisco AI Defense custom policy block" {
		return t
	}
	// "Cisco AI Defense: <rule>[, <rule>...]" — rule names are
	// hand-authored labels from the AID cloud catalog. Validate the
	// suffix consists entirely of comma-separated tokens made of
	// letters, digits, spaces, and a small punctuation set so we
	// don't accidentally allow through a user-controlled string that
	// happens to prepend "Cisco AI Defense: " (e.g. a prompt-injection
	// attempt echoing the phrase).
	suffix, ok := strings.CutPrefix(t, aidPrefix+": ")
	if !ok {
		return ""
	}
	if suffix == "" || len(suffix) > 256 {
		return ""
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == ' ' || c == '-' || c == '_' || c == ',' || c == '.' || c == '&':
		default:
			return ""
		}
	}
	return t
}

// redactReasonTokenDepth is the depth-bounded worker for
// redactReasonToken. We recurse once when a `<wrapper>: <body>` shape
// wraps a further rule-id:literal; anything deeper collapses to a
// flat ForSinkString so pathological inputs cannot blow the stack.
func redactReasonTokenDepth(t string, depth int) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	const maxReasonDepth = 2
	if depth >= maxReasonDepth {
		if isSafeReasonToken(t) {
			return t
		}
		return LegacyV7String(t)
	}
	if idx := strings.Index(t, ": "); idx > 0 {
		prefix := t[:idx]
		rest := t[idx+2:]
		if len(prefix) <= 128 && isRuleIDChars(prefix) {
			if isSafeReasonToken(rest) {
				return prefix + ": " + rest
			}
			// Recurse so the inner clause keeps rule IDs that
			// sit after the outer `wrapper: ` prefix.
			return prefix + ": " + redactReasonTokenDepth(rest, depth+1)
		}
	}
	// "<rule-id>:<description>" — colon-delimited without space.
	// The rule-id prefix is always a finite, hand-authored set of
	// uppercase identifiers (isRuleIDChars). Description text
	// after the colon is authored but can include matched
	// literals verbatim (e.g. `SEC-ANTHROPIC:API key sk-ant-...`
	// or the SSN-by-regex `PII-SSN:123-45-6789` shape emitted by
	// some scanners, or the adversarial `SEC-OPENAI:sk-proj-…`
	// where a scanner echoes the matched literal into the title).
	//
	// We keep the ID so operators still see what tripped, and
	// ALWAYS scrub the rest — even when it happens to look
	// rule-id-shaped — so a short all-alphanumeric-with-hyphens
	// secret cannot ride through on the rule-id allow-list.
	if idx := strings.IndexByte(t, ':'); idx > 0 && !strings.Contains(t[:idx], " ") {
		prefix := t[:idx]
		rest := t[idx+1:]
		if len(prefix) <= 128 && isRuleIDChars(prefix) && rest != "" {
			if isPlaceholder(rest) {
				return prefix + ":" + rest
			}
			return prefix + ":" + LegacyV7String(rest)
		}
	}
	if isSafeReasonToken(t) {
		return t
	}
	if redacted, ok := redactWhitespaceTokens(t); ok {
		return redacted
	}
	if eq := strings.IndexByte(t, '='); eq > 0 && !strings.ContainsAny(t, " \t") {
		key := t[:eq]
		val := t[eq+1:]
		if len(key) <= 128 && isRuleIDChars(key) {
			if val == "" {
				return key + "="
			}
			if isPlaceholder(val) {
				return key + "=" + val
			}
			return key + "=" + LegacyV7String(val)
		}
	}
	return LegacyV7String(t)
}

// redactWhitespaceTokens handles "key=value [key=value …]" audit
// strings where values themselves may contain whitespace.
func redactWhitespaceTokens(clause string) (string, bool) {
	boundaries := findKVBoundaries(clause)
	if len(boundaries) == 0 {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(clause))
	for i, start := range boundaries {
		if i == 0 && start > 0 {
			leading := strings.TrimSpace(clause[:start])
			if leading != "" {
				b.WriteString(LegacyV7String(leading))
				b.WriteByte(' ')
			}
		}
		end := len(clause)
		if i+1 < len(boundaries) {
			end = boundaries[i+1]
		}
		segment := clause[start:end]
		segment = strings.TrimRight(segment, " \t")
		eq := strings.IndexByte(segment, '=')
		if eq < 0 {
			b.WriteString(LegacyV7String(segment))
		} else {
			key := segment[:eq]
			value := segment[eq+1:]
			b.WriteString(key)
			b.WriteByte('=')
			switch {
			case value == "":
			case isPlaceholder(value):
				b.WriteString(value)
			case isSafeKVValue(value):
				b.WriteString(value)
			default:
				b.WriteString(LegacyV7String(value))
			}
		}
		if i+1 < len(boundaries) {
			b.WriteByte(' ')
		}
	}
	return b.String(), true
}

// findKVBoundaries returns the byte offsets at which a new
// "<key>=" token begins inside clause.
func findKVBoundaries(clause string) []int {
	var out []int
	n := len(clause)
	i := 0
	scanKey := func(p int) int {
		start := p
		hasLetter := false
	keyLoop:
		for p < n {
			c := clause[p]
			switch {
			case c >= 'a' && c <= 'z':
				hasLetter = true
			case c >= 'A' && c <= 'Z':
				hasLetter = true
			case c >= '0' && c <= '9':
			case c == '_' || c == '-' || c == '.' || c == '/':
			default:
				break keyLoop
			}
			p++
		}
		if !hasLetter || p == start || p >= n || clause[p] != '=' {
			return -1
		}
		return p
	}
	skipPlaceholder := func(p int) int {
		if p >= n || clause[p] != '<' {
			return -1
		}
		if strings.HasPrefix(clause[p:], "<redacted") || strings.HasPrefix(clause[p:], "<empty>") {
			end := strings.IndexByte(clause[p:], '>')
			if end < 0 {
				return -1
			}
			return p + end + 1
		}
		return -1
	}
	if eq := scanKey(0); eq >= 0 {
		out = append(out, 0)
		i = eq + 1
		if skipped := skipPlaceholder(i); skipped > 0 {
			i = skipped
		}
	}
	for i < n {
		if skipped := skipPlaceholder(i); skipped > 0 {
			i = skipped
			continue
		}
		c := clause[i]
		if c != ' ' && c != '\t' {
			i++
			continue
		}
		j := i
		for j < n && (clause[j] == ' ' || clause[j] == '\t') {
			j++
		}
		if eq := scanKey(j); eq >= 0 {
			out = append(out, j)
			i = eq + 1
			if skipped := skipPlaceholder(i); skipped > 0 {
				i = skipped
			}
			continue
		}
		i = j + 1
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

// Evidence redacts a free-form text window around a regex match.
// matchStart and matchEnd are byte offsets into the original content.
func Evidence(content string, matchStart, matchEnd int) string {
	if Reveal() {
		return content
	}
	return ForSinkEvidence(content, matchStart, matchEnd)
}

// ForSinkEvidence is the Reveal-bypassing compatibility projection. It is
// idempotent over its own placeholder shape and honors DisableAll.
func ForSinkEvidence(content string, matchStart, matchEnd int) string {
	if DisableAll() {
		return content
	}
	return LegacyV7Evidence(content, matchStart, matchEnd)
}

func redactEvidence(content string, matchStart, matchEnd int) string {
	return LegacyV7Evidence(content, matchStart, matchEnd)
}

// LegacyV7Evidence applies the exact v7 evidence projection without
// consulting environment variables or mutable package state. Coordinates are
// included only when supplied as a valid non-empty range; the helper never
// derives or invents them.
func LegacyV7Evidence(content string, matchStart, matchEnd int) string {
	if content == "" {
		return "<empty>"
	}
	if isEvidencePlaceholder(content) {
		return content
	}
	if matchStart >= 0 && matchEnd > matchStart {
		return fmt.Sprintf("<redacted-evidence len=%d match=[%d:%d] sha=%s>",
			len(content), matchStart, matchEnd, hashPrefix(content))
	}
	return fmt.Sprintf("<redacted-evidence len=%d sha=%s>",
		len(content), hashPrefix(content))
}

// hashPrefix returns the leading hashPrefixHex hex characters of
// SHA-256(s).
func hashPrefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:hashPrefixHex]
}

// safeEnumValues is the positive catalog of operator-trusted enum
// constants that pass through reason redaction unchanged on either
// the value side of audit "key=value" pairs OR as standalone tokens.
//
// Hand-curated. Extend with review when new enum constants ship.
// Every entry must be either a documented policy enum, severity
// label, target kind, connector name, transport / HTTP verb, or
// boolean / outcome word. Anything that could plausibly hold
// user-supplied content (paths, IDs, names, URLs, model names with
// version numbers, prompt fragments) MUST NOT be added here.
var safeEnumValues = map[string]struct{}{
	// policy verdicts and modes
	"allow": {}, "allowed": {}, "block": {}, "blocked": {}, "deny": {}, "denied": {},
	"observe": {}, "action": {}, "warn": {}, "warning": {}, "monitor": {}, "enforce": {},
	"learn": {}, "off": {}, "on": {}, "true": {}, "false": {}, "none": {}, "null": {},
	// outcome states
	"unknown": {}, "error": {}, "ok": {}, "success": {}, "failure": {}, "partial": {},
	"clean": {}, "rejected": {}, "quarantine": {}, "quarantined": {}, "skip": {}, "skipped": {},
	"inherit": {}, "require": {}, "optional": {}, "enabled": {}, "disabled": {},
	// direction / phase
	"prompt": {}, "response": {}, "request": {}, "completion": {}, "tool": {}, "tool_use": {},
	"tool_result": {}, "inspect": {}, "admit": {}, "drift": {}, "baseline": {}, "new": {},
	"removed": {}, "updated": {}, "modified": {}, "added": {}, "deleted": {}, "created": {},
	// severity (uppercase)
	"INFO": {}, "LOW": {}, "MEDIUM": {}, "HIGH": {}, "HIGH_BUG": {}, "CRITICAL": {},
	"BUG": {}, "UNKNOWN": {}, "ERROR": {}, "DEBUG": {}, "TRACE": {}, "WARN": {},
	"WARNING": {}, "FATAL": {},
	// target kinds and connectors
	"skill": {}, "plugin": {}, "mcp": {}, "codeguard": {}, "scanner": {},
	"openai": {}, "anthropic": {}, "google": {}, "bedrock": {}, "azure": {}, "ollama": {},
	"geminicli": {}, "codex": {}, "openclaw": {}, "cursor": {}, "claudecode": {},
	"zeptoclaw": {}, "litellm": {}, "bifrost": {}, "openrouter": {}, "vertex": {},
	// transport / wire format
	"stdio": {}, "sse": {}, "websocket": {}, "http": {}, "https": {}, "tcp": {}, "udp": {},
	"json": {}, "yaml": {}, "toml": {}, "form": {}, "text": {},
	// HTTP verbs
	"GET": {}, "POST": {}, "PUT": {}, "DELETE": {}, "PATCH": {}, "HEAD": {}, "OPTIONS": {},
	// LLM message roles
	"user": {}, "system": {}, "assistant": {}, "developer": {}, "tool_calls": {},
	// generic boolean / discoverable defaults
	"yes": {}, "no": {}, "auto": {}, "manual": {}, "any": {}, "all": {},
	// asset / registry policy single-word enums (multi-word forms
	// like "not-in-approved-registry" go through isLowercaseKebabReason)
	"unregistered": {}, "registered": {}, "configured": {}, "unconfigured": {},
	"required": {}, "approved": {}, "pending": {},
	"baselined": {}, "snapshot": {}, "current": {}, "stale": {},
}

// isCanonicalID reports whether s is an UPPER-CASE rule/canonical
// identifier that contains at least one separator from the rule-ID
// character class. Used as a safe-pass shape on the value side of
// audit "key=value" pairs and as a standalone reason token.
//
// The two requirements work together to reject the credential
// shapes from the report:
//
//   - "AKIAIOSFODNN7EXAMPLE" — uppercase but NO separator → rejected
//   - "sk-test-123"          — has separator but lowercase → rejected
//   - "hunter-2"             — lowercase + separator        → rejected
//   - "SEC-AWS-KEY"          — uppercase + separator        → ACCEPTED
//   - "PII-SSN-US"           — uppercase + separator        → ACCEPTED
//   - "CODEGUARD-0-XSS"      — uppercase digits + separator → ACCEPTED
func isCanonicalID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	hasUpper := false
	hasSeparator := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '/' || c == ':':
			hasSeparator = true
		default:
			return false
		}
	}
	return hasUpper && hasSeparator
}

// engineRuleIDPrefixes is the bounded catalog of dotted lowercase
// rule-ID prefixes that the DefenseClaw engine actually emits
// (`pii.phone`, `policy.admission`, `scan.skill.installed`, …).
// Anything that looks dotted but does NOT start with one of these
// prefixes is treated as user-supplied content (URLs, hostnames,
// version strings, free-form session tokens) and routed to the
// redactor.
var engineRuleIDPrefixes = []string{
	"pii.", "policy.", "scan.", "audit.", "judge.", "guardrail.",
	"sec.", "firewall.", "sandbox.", "inspect.", "tool.", "prompt.",
	"code.", "event.", "admission.", "drift.", "watcher.", "engine.",
	"connector.", "rule.",
}

// isLowercaseKebabReason reports whether s is a multi-word
// lowercase reason / status / surface enum that uses '-' or '_' to
// separate purely alphabetic segments. Used to keep operator-facing
// policy reason codes readable (`not-in-approved-registry`,
// `registry-required-but-empty`, `default-deny`, `prompt_expansion`,
// `pre_tool_use`).
//
// The "no digits" rule is the security boundary that distinguishes
// these enums from credential shapes called out in the report:
//
//   - sk-test-123  → digits      → rejected
//   - hunter-2     → digit       → rejected
//   - abc.def      → wrong sep   → rejected
//   - api_key      → no sep word → rejected (only single segment)
//   - default-deny → all letters → ACCEPTED
//
// We also require at least two segments (so a bare lowercase word
// without a separator falls back to the safeEnumValues catalog).
func isLowercaseKebabReason(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	hasSep := false
	prevWasSep := true
	segCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			if prevWasSep {
				segCount++
			}
			prevWasSep = false
		case c == '-' || c == '_':
			if prevWasSep {
				return false
			}
			hasSep = true
			prevWasSep = true
		default:
			return false
		}
	}
	if prevWasSep {
		return false
	}
	return hasSep && segCount >= 2
}

// isLowercaseDottedRuleID reports whether s is a documented engine
// rule-ID shape that uses '.' as the segment separator (the
// convention used for `pii.phone`, `pii.email`, `policy.admission`,
// `scan.skill.installed`, …). The narrow "must start with a known
// engine prefix" requirement keeps short hyphenated credentials
// like `sk-test-123` and free-form session tokens like `abc.def`
// from being mistaken for engine rule IDs.
func isLowercaseDottedRuleID(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	matched := false
	for _, p := range engineRuleIDPrefixes {
		if strings.HasPrefix(s, p) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	hasDot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_':
		case c == '.':
			hasDot = true
		default:
			return false
		}
	}
	return hasDot
}

// isSafeReasonToken is the positive-catalog allow-list for plain
// reason tokens. Replaces the previous "any rule-id-shape with a
// separator up to 32 bytes" predicate, which let credential shapes
// like `sk-test-123` or `password=hunter-2` pass unchanged.
//
// A token passes only if one of the following holds:
//
//  1. It is a `key=value` pair where the key is well-formed and the
//     value matches isSafeKVValue (which itself uses positive catalogs).
//  2. It is a known enum constant (safeEnumValues — case-sensitive).
//  3. It is an UPPER-CASE canonical ID with at least one separator.
//  4. It is a lowercase dotted engine rule ID (pii.phone, pii.email).
//
// Anything else routes through the per-token redactor.
func isSafeReasonToken(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	if eq := strings.IndexByte(t, '='); eq > 0 {
		k := t[:eq]
		v := t[eq+1:]
		if !isReasonKey(k) {
			return false
		}
		return isSafeKVValue(v)
	}
	if len(t) > 64 {
		return false
	}
	if _, ok := safeEnumValues[t]; ok {
		return true
	}
	if isCanonicalID(t) {
		return true
	}
	return isLowercaseDottedRuleID(t)
}

// isReasonKey reports whether k is a well-formed key on the left side
// of an audit "key=value" pair. The security boundary lives on the
// value side (isSafeKVValue); keys may use the broad rule-id charset
// because they are field names rather than user content.
func isReasonKey(k string) bool {
	if len(k) == 0 || len(k) > 32 {
		return false
	}
	return isRuleIDChars(k)
}

// isSafeKVValue is the positive-catalog allow-list for the value side
// of an audit "key=value" pair. Comma-separated lists pass when every
// segment passes individually; the whole list is capped at 256 bytes
// so pathological inputs cannot inflate the safe surface.
func isSafeKVValue(v string) bool {
	if v == "" {
		return false
	}
	if strings.IndexByte(v, ',') >= 0 {
		if len(v) > 256 {
			return false
		}
		for _, seg := range strings.Split(v, ",") {
			if !isSafeSingleKVValue(seg) {
				return false
			}
		}
		return true
	}
	return isSafeSingleKVValue(v)
}

// isSafeSingleKVValue is the single-segment form of isSafeKVValue.
// Accepts (in order):
//
//   - Pure-digit values up to 6 chars (counts, exit codes, ports).
//   - Known enum constants (safeEnumValues — case-sensitive).
//   - Lowercase kebab/snake reason codes (`not-in-approved-registry`).
//   - UPPER-CASE canonical IDs with a separator (SEC-AWS-KEY, …).
//   - Lowercase dotted engine rule IDs (pii.phone, …).
//   - Short bare alphanumeric tokens (asset names, surfaces) up to
//     compactRuleIDMaxBytes / 11 bytes — long enough for "rogue",
//     "tool", "prompt", "skill", short MCP names, but well below the
//     length of any credential the report calls out (AWS=20, OpenAI=51+).
//
// All credential-shaped strings the redactor must catch
// (sk-test-123, hunter-2, dev/token, abc.def with non-engine prefix,
// MySecretP4ssword) fail every positive check and route to the
// redactor.
func isSafeSingleKVValue(v string) bool {
	if v == "" {
		return false
	}
	onlyDigits := true
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			onlyDigits = false
			break
		}
	}
	if onlyDigits {
		return len(v) <= 6
	}
	if _, ok := safeEnumValues[v]; ok {
		return true
	}
	if isLowercaseKebabReason(v) {
		return true
	}
	if isCanonicalID(v) {
		return true
	}
	if isLowercaseDottedRuleID(v) {
		return true
	}
	return isShortAlphanumericToken(v)
}

// isShortAlphanumericToken reports whether v is a bare alphanumeric
// token short enough that it cannot encode a credential of interest.
// The 11-byte cap is the same compactRuleIDMaxBytes used by the
// standalone-token check; tokens at or below this length are
// considered safe to display verbatim because:
//
//   - AWS access keys are 20 chars (AKIAIOSFODNN7EXAMPLE).
//   - OpenAI keys are 51+ chars (sk-…48 hex…).
//   - GitHub PATs are 40 chars (ghp_…).
//   - JWT tokens are 200+ chars.
//   - Session IDs are typically ≥22 base64 chars.
//
// Asset / surface / role identifiers that legitimately appear in
// audit reasons (rogue, tool, skill, prompt, mcp, none) are well
// under the cap.
func isShortAlphanumericToken(v string) bool {
	if len(v) == 0 || len(v) > compactRuleIDMaxBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// isRuleIDChars reports whether every byte of s is in the allow-list
// for rule identifiers AND s contains at least one letter. The "at
// least one letter" requirement rejects pure-digit PII shapes
// (phones, SSNs, dates) that would otherwise match the character
// class.
func isRuleIDChars(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLetter = true
		case c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.' || c == ':' || c == '/':
		default:
			return false
		}
	}
	return hasLetter
}
