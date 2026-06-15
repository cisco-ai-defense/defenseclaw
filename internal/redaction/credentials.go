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
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrCredentialDetected is returned by AssertNoCredentials when at least
// one supplied string contains a known API-key / token prefix. Callers
// can use errors.Is to branch on the dev-vs-prod behavior:
//
//   - Dev (DEFENSECLAW_DEV=1, DEFENSECLAW_TEST=1, or `go test`): callers
//     of MustAssertNoCredentials panic so the offending field is fixed
//     before merge. The crash trace points at the emit-site.
//   - Prod (default): callers log a structured warning and drop the
//     offending string; the telemetry pipeline never carries the
//     credential, but the gateway also doesn't crash.
//
// Plan B6 / S0.10 — defensive guard for downstream code paths that
// inadvertently route an API key into a telemetry field that should
// only ever carry routing metadata (Host, Path, Reason).
var ErrCredentialDetected = errors.New("redaction: known credential prefix found in telemetry field")

// credentialPrefix is a short, case-sensitive prefix that uniquely
// identifies a popular cloud-provider credential format. The prefix
// alone is enough to fail the scrub guard — we never ship the full
// suffix to a panic message or returned error, only the prefix +
// position so the operator can find and fix the offending emit.
//
// Sources:
//
//   - sk-, sk-proj-, sk-ant-, sk-or-: OpenAI / Anthropic / Anthropic
//     Claude / OpenRouter API keys.
//   - sk_live_, sk_test_, pk_live_, pk_test_: Stripe.
//   - AKIA, ASIA, AROA, AGPA, AIDA, AIPA, ANPA, ANVA: AWS access
//     key IDs. Short by themselves so we also require a length floor.
//   - AIza: Google API keys (35-char suffix). Length floor applied.
//   - ghp_, gho_, ghu_, ghs_, ghr_: GitHub personal/OAuth/user/server/
//     refresh tokens.
//   - xoxb-, xoxp-, xoxa-, xoxr-: Slack bot/user/app/refresh tokens.
//   - eyJ: JWT (base64url-encoded JSON header). Length floor applied
//     because "eyJ" alone is too short to indicate a token; we require
//     the next-but-one period a JWT must have.
type credentialPrefix struct {
	prefix      string
	minLen      int    // total minimum length that must follow the prefix
	requireRune byte   // optional: a specific byte that must appear after the prefix (e.g. '.' for JWT)
	label       string // operator-facing identifier (never the value itself)
}

var credentialPrefixes = []credentialPrefix{
	{prefix: "sk-proj-", minLen: 24, label: "openai-project-key"},
	{prefix: "sk-ant-", minLen: 24, label: "anthropic-key"},
	{prefix: "sk-or-", minLen: 24, label: "openrouter-key"},
	{prefix: "sk-", minLen: 24, label: "openai-key"},
	{prefix: "sk_live_", minLen: 24, label: "stripe-secret-live"},
	{prefix: "sk_test_", minLen: 24, label: "stripe-secret-test"},
	{prefix: "pk_live_", minLen: 24, label: "stripe-publishable-live"},
	{prefix: "pk_test_", minLen: 24, label: "stripe-publishable-test"},
	{prefix: "AKIA", minLen: 20, label: "aws-access-key"},
	{prefix: "ASIA", minLen: 20, label: "aws-session-token"},
	{prefix: "AROA", minLen: 20, label: "aws-role-key"},
	{prefix: "AGPA", minLen: 20, label: "aws-group-key"},
	{prefix: "AIDA", minLen: 20, label: "aws-user-key"},
	{prefix: "AIPA", minLen: 20, label: "aws-instance-profile-key"},
	{prefix: "ANPA", minLen: 20, label: "aws-managed-policy-key"},
	{prefix: "ANVA", minLen: 20, label: "aws-vpc-endpoint-key"},
	{prefix: "AIza", minLen: 39, label: "google-api-key"},
	{prefix: "ghp_", minLen: 36, label: "github-pat"},
	{prefix: "gho_", minLen: 36, label: "github-oauth"},
	{prefix: "ghu_", minLen: 36, label: "github-user-server"},
	{prefix: "ghs_", minLen: 36, label: "github-server"},
	{prefix: "ghr_", minLen: 36, label: "github-refresh"},
	{prefix: "xoxb-", minLen: 24, label: "slack-bot"},
	{prefix: "xoxp-", minLen: 24, label: "slack-user"},
	{prefix: "xoxa-", minLen: 24, label: "slack-app"},
	{prefix: "xoxr-", minLen: 24, label: "slack-refresh"},
	{prefix: "eyJ", minLen: 32, requireRune: '.', label: "jwt"},
}

// AssertNoCredentials returns an error wrapping ErrCredentialDetected
// when any input string contains a known API-key prefix above the
// minimum length floor. The label of the matched prefix and the field
// position are included in the error message for triage; the matched
// substring itself is NEVER included.
//
// Returns nil for the common case (no credential prefix found). Cheap
// in the hot path — runs strings.Index per-prefix-per-input which is
// O(prefixes * total length).
func AssertNoCredentials(values ...string) error {
	for idx, v := range values {
		if v == "" {
			continue
		}
		if label := scanForCredentialPrefix(v); label != "" {
			return fmt.Errorf("%w: field[%d] matched prefix=%s", ErrCredentialDetected, idx, label)
		}
	}
	return nil
}

// MustAssertNoCredentials runs AssertNoCredentials and panics in dev
// when a credential is found. In prod (the default) it logs to stderr
// and returns silently. The dev/prod toggle reads three env vars:
//
//   - DEFENSECLAW_DEV=1           — explicit dev opt-in
//   - DEFENSECLAW_REVEAL_PII=1    — also opts dev-mode reveal flag
//   - GO_TEST=1 / running under `go test` (sensed via os.Args[0])
//
// The panic body never includes the offending string — only the field
// position and the matched prefix label so the crash trace stays
// safe to share in incident channels.
func MustAssertNoCredentials(values ...string) {
	err := AssertNoCredentials(values...)
	if err == nil {
		return
	}
	if isCredentialScrubDevMode() {
		// Dev: hard fail so the offending emit-site is fixed before merge.
		panic(err.Error())
	}
	// Prod: structured warning to stderr; the telemetry pipeline does
	// NOT carry the credential because the caller's job is to scrub
	// the field itself; we're a defense-in-depth canary here.
	fmt.Fprintf(os.Stderr, "[redaction] WARN credential prefix in telemetry field: %v\n", err)
}

func scanForCredentialPrefix(v string) string {
	for _, cp := range credentialPrefixes {
		i := strings.Index(v, cp.prefix)
		if i < 0 {
			continue
		}
		// Don't count a prefix that's itself a substring of a longer
		// prefix we already declared. e.g. "sk-" is matched by
		// "sk-proj-" first because the slice puts the longer prefix
		// first; once a hit lands, we return immediately.
		tail := v[i+len(cp.prefix):]
		if len(tail) < cp.minLen-len(cp.prefix) {
			continue
		}
		if cp.requireRune != 0 && !strings.ContainsRune(tail, rune(cp.requireRune)) {
			continue
		}
		return cp.label
	}
	return ""
}

// isCredentialScrubDevMode mirrors the DEFENSECLAW_REVEAL_PII gate
// without importing the surrounding env helpers — kept local so the
// scrub guard never crashes a prod sidecar that happens to flap the
// reveal flag for incident triage.
func isCredentialScrubDevMode() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_DEV"))); v == "1" || v == "true" {
		return true
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_TEST"))); v == "1" || v == "true" {
		return true
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("GO_TEST"))); v == "1" || v == "true" {
		return true
	}
	// Heuristic for `go test` runs that don't set GO_TEST: the test
	// binary's argv[0] ends with ".test".
	if a := os.Args; len(a) > 0 && strings.HasSuffix(a[0], ".test") {
		return true
	}
	return false
}
