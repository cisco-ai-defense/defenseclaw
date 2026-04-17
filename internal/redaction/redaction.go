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
	"strings"
	"unicode/utf8"
)

// revealEnvVar is the single environment variable that opts logs into
// emitting raw values in place of redacted placeholders. Kept as an
// unexported constant so callers cannot accidentally introduce parallel
// flags that defeat the audit story.
const revealEnvVar = "DEFENSECLAW_REVEAL_PII"

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

// ForSinkString is the Reveal-bypassing variant of String. Always
// returns the redacted placeholder regardless of the reveal flag.
// Use for anything destined for SQLite / Splunk / OTel / webhooks /
// HTTP responses to remote callers.
//
// Idempotent: a value already shaped like a redaction placeholder is
// returned unchanged so layered helpers don't lose the original hash
// or length on a second pass.
func ForSinkString(s string) string {
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

// isPlaceholder reports whether s is one of our own redaction
// placeholder shapes. Used to make the ForSink* helpers idempotent.
func isPlaceholder(s string) bool {
	if s == "<empty>" {
		return true
	}
	if !strings.HasPrefix(s, "<redacted") || !strings.HasSuffix(s, ">") {
		return false
	}
	if len(s) > 200 {
		return false
	}
	return !strings.ContainsAny(s, "\n\r")
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

// ForSinkEntity is the Reveal-bypassing variant of Entity. Idempotent
// over its own placeholder shape.
func ForSinkEntity(value string) string {
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

// ForSinkMessageContent is the Reveal-bypassing variant of
// MessageContent. Idempotent.
func ForSinkMessageContent(content string) string {
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

// ForSinkReason is the Reveal-bypassing variant of Reason.
//
// Idempotent: if the input has already been through redaction (i.e.
// contains "<redacted" markers and no other content), it is returned
// unchanged.
func ForSinkReason(reason string) string {
	if reason == "" {
		return ""
	}
	if isAlreadyRedacted(reason) {
		return reason
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
// shapes or a "key: <redacted...>" pair.
func isRedactedToken(tok string) bool {
	switch {
	case strings.HasPrefix(tok, "<redacted"):
		return strings.HasSuffix(tok, ">")
	case tok == "<empty>":
		return true
	}
	if idx := strings.Index(tok, ": "); idx > 0 {
		prefix := tok[:idx]
		rest := tok[idx+2:]
		if isRuleIDChars(prefix) && strings.HasPrefix(rest, "<redacted") && strings.HasSuffix(rest, ">") {
			return true
		}
	}
	return false
}

// redactReasonToken applies the per-clause redaction policy.
//
// Recognized shapes in priority order:
//
//  1. "<rule-id>: <description>"     — space-delimited; keep ID, scrub or keep desc
//  2. "<rule-id>:<description>"      — colon-delimited (our standard finding
//     format, e.g. "SEC-ANTHROPIC:API key ...") — keep ID,
//     redact the description wholesale because it is free-form
//     text that routinely embeds the offending literal
//  3. "<key>=<value>" (no whitespace) — classic audit key=value
//  4. Multi-pair whitespace clause   — delegated to redactWhitespaceTokens
//  5. Plain safe reason token        — rule-id characters only
//  6. Fallback                       — whole-token redaction
func redactReasonToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if idx := strings.Index(t, ": "); idx > 0 {
		prefix := t[:idx]
		rest := t[idx+2:]
		if len(prefix) <= 128 && isRuleIDChars(prefix) {
			if isSafeReasonToken(rest) {
				return prefix + ": " + rest
			}
			return prefix + ": " + ForSinkString(rest)
		}
	}
	// "<rule-id>:<description>" — colon-delimited without space.
	// The rule-id prefix is always a finite, hand-authored set of
	// uppercase identifiers (isRuleIDChars). Description text
	// after the colon is authored but can include matched
	// literals verbatim (e.g. `SEC-ANTHROPIC:API key sk-ant-...`
	// or the SSN-by-regex `PII-SSN:123-45-6789` shape emitted by
	// some scanners). We keep the ID so operators still see what
	// tripped, and scrub the rest so the literal never hits a
	// persistent sink.
	if idx := strings.IndexByte(t, ':'); idx > 0 && !strings.Contains(t[:idx], " ") {
		prefix := t[:idx]
		rest := t[idx+1:]
		if len(prefix) <= 128 && isRuleIDChars(prefix) && rest != "" {
			if isSafeReasonToken(rest) {
				return prefix + ":" + rest
			}
			return prefix + ":" + ForSinkString(rest)
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
			return key + "=" + ForSinkString(val)
		}
	}
	return ForSinkString(t)
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
				b.WriteString(ForSinkString(leading))
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
			b.WriteString(ForSinkString(segment))
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
				b.WriteString(ForSinkString(value))
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
				goto done
			}
			p++
		}
	done:
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

// ForSinkEvidence is the Reveal-bypassing variant of Evidence.
// Idempotent over its own placeholder shape.
func ForSinkEvidence(content string, matchStart, matchEnd int) string {
	if content == "" {
		return "<empty>"
	}
	if strings.HasPrefix(content, "<redacted-evidence") && strings.HasSuffix(content, ">") {
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

// isSafeReasonToken reports whether a substring of a verdict reason
// can be emitted verbatim.
// isSafeReasonToken is the allow-list for plain reason tokens
// (i.e. no '=' pair). Rule IDs and canonical IDs are the only
// hand-authored shapes we trust here; everything else must go
// through the redactor.
//
// The 32-byte cap matches isSafeSingleKVValue so that a long
// alphanumeric+dash literal (e.g. a leaked API key of the form
// "sk-ant-api03-abcdefghij…") does NOT slip through merely
// because it happens to share the rule-id character class.
// Real rule IDs top out around 20 chars (SEC-ANTHROPIC,
// PII-SSN-US, …) so 32 leaves headroom for canonical-id
// extensions like SEC-GITHUB-APP-TOKEN without letting
// genuine secrets pass.
func isSafeReasonToken(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	if eq := strings.IndexByte(t, '='); eq > 0 {
		k := t[:eq]
		v := t[eq+1:]
		if len(k) > 32 {
			return false
		}
		return isRuleIDChars(k) && isSafeKVValue(v)
	}
	if len(t) > 32 {
		return false
	}
	return isRuleIDChars(t)
}

// isSafeKVValue is the value-side allow-list for "key=value" tokens.
// Letter-bearing values follow the rule-id charset (≤32 chars);
// letter-less values (pure digits, digits+hyphen, digits+colon) are
// capped at 6 characters so phone numbers, SSNs, and dates are
// always redacted.
//
// Comma is treated as a list separator so that audit fields like
//
//	canonical=SEC-AWS-KEY,SEC-GITHUB-TOKEN
//
// pass verbatim. Every comma-separated segment must itself be a
// safe value under the same rules; the whole list is capped at 256
// characters to keep pathological inputs from surfacing as "safe".
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

// isSafeSingleKVValue is the single-token form of isSafeKVValue.
func isSafeSingleKVValue(v string) bool {
	if v == "" {
		return false
	}
	hasLetter := false
	for i := 0; i < len(v); i++ {
		c := v[i]
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
	if hasLetter {
		return len(v) <= 32
	}
	return len(v) <= 6
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
