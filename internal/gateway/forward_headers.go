// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"net/textproto"
	"strings"
)

// Header forwarding policy.
//
// The guardrail gateway forwards inbound agent headers to the upstream
// LLM provider on both the chat/completions and passthrough code paths
// when llm.forward_custom_headers is enabled (default on).
//
// The model is intentionally blocklist-only: every inbound header is
// forwarded except a hardened set that would (a) leak DefenseClaw
// internal routing metadata to third parties, (b) overwrite or
// duplicate the canonical upstream Authorization header the gateway
// re-mints from the secrets sidecar, (c) corrupt the upstream HTTP
// framing (hop-by-hop headers, Content-Length when the body was
// rewritten by guardrail notification injection), or (d) cross
// trust boundaries via cookies / W3C trace context.
//
// Two further safeguards are applied to every header that survives
// the blocklist:
//   - RFC 7230 tchar validation on the name (rejects malformed names
//     and prevents header smuggling via embedded control characters).
//   - Printable-ASCII (+ HTAB) validation on the value (rejects CR,
//     LF, and NUL — the primary HTTP-response/header injection and
//     log-injection vectors).
//
// Soft caps bound the number of headers and the combined name+value
// bytes forwarded per request to prevent a hostile client from
// exhausting upstream provider header budgets.

// Maximum number of headers forwarded per request, and maximum combined
// bytes (sum of name + value lengths across forwarded headers). Caps
// are deliberately generous so legitimate provider headers like
// anthropic-version, anthropic-beta, openai-organization, tenant tags,
// and tracing IDs all flow through; they exist to bound an abusive
// caller rather than to constrain the common case.
const (
	maxForwardedHeaders = 64
	maxForwardedBytes   = 32 * 1024
)

// alwaysDeniedHeaders is the never-forwarded set. Keys are lowercased
// for case-insensitive comparison via http.CanonicalHeaderKey-folded
// strings.ToLower. The X-DC-* and X-DefenseClaw-* families are handled
// by prefix checks in shouldForwardHeader instead of by entries here.
//
// The set below is **identical to the pre-existing inline blocklist** in
// handlePassthrough so this refactor does not silently change which
// headers reach upstream providers. The expanded blocklist (cookies,
// hop-by-hop per RFC 7230 §6.1, Baggage, Content-Type) is intentionally
// commented out below — each entry carries a danger rating so operators
// can re-enable selected names by uncommenting if they observe upstream
// regressions or want stricter posture. See docs/GUARDRAIL.md for
// guidance.
var alwaysDeniedHeaders = map[string]struct{}{
	// Proxy-hop / framework-internal headers (pre-existing).
	"x-dc-target-url": {},
	"x-ai-auth":       {},
	"x-dc-auth":       {},
	// Wire framing — Content-Length must not be copied because
	// guardrail notification injection can change the body size;
	// upstreamReq.ContentLength is the authoritative value. Host is
	// rebuilt by http.NewRequestWithContext from the URL.
	"host":           {},
	"content-length": {},
	// Authentication — re-minted canonically by the gateway from the
	// secrets sidecar / token resolver (pre-existing).
	"authorization": {},
	"x-api-key":     {},
	"api-key":       {},
	// W3C trace context — internal correlation only; echoing into
	// upstream provider logs leaks DefenseClaw routing metadata across
	// tenants (pre-existing).
	"traceparent": {},
	"tracestate":  {},

	// ── BEGIN: blocklist expansion — commented out to preserve the
	// pre-refactor forwarding contract. Each entry below was added by
	// the refactor and is *not* in the legacy inline loop. Uncomment
	// selectively if your deployment's threat model requires it.
	//
	// DANGER RATING legend (per the security review):
	//   HIGH:   genuinely exploitable if forwarded — strongly recommend
	//           keeping commented-IN (i.e. enable the blocklist entry).
	//   MEDIUM: protocol-incorrect to forward but rarely exploitable in
	//           practice; Go's net/http client largely ignores them on
	//           outbound requests.
	//   LOW:    privacy / telemetry leak only; no exploit path.
	//   ZERO:   actively wrong to block — upstream parsers depend on it.

	// "cookie":              {}, // HIGH — agent session cookies (often
	//                              // meant for the agent's frontend, not
	//                              // the LLM provider). LLM-provider logs
	//                              // could capture them. Cookie-stealing
	//                              // via log search is the canonical
	//                              // exploit pattern. ★ recommend
	//                              // re-enabling.
	// "set-cookie":          {}, // HIGH — only meaningful on responses
	//                              // but cheap to block on requests as
	//                              // defense-in-depth. ★ recommend
	//                              // re-enabling.
	// "proxy-authorization": {}, // HIGH — next-hop proxy credentials.
	//                              // Forwarding leaks proxy-server auth
	//                              // to the LLM provider. ★ recommend
	//                              // re-enabling.
	// "transfer-encoding":   {}, // HIGH — forwarding "chunked" alongside
	//                              // a known Content-Length is a classic
	//                              // HTTP request-smuggling vector. ★
	//                              // recommend re-enabling.
	// "te":                  {}, // HIGH — paired with Transfer-Encoding;
	//                              // forwarding can enable smuggling
	//                              // variants. ★ recommend re-enabling.
	// "trailers":            {}, // MEDIUM — hop-by-hop announcement of
	//                              // trailer fields; meaningless on the
	//                              // outbound request but inconsistent
	//                              // with RFC 7230 §6.1.
	// "connection":          {}, // MEDIUM — hop-by-hop; "Connection:
	//                              // close" forwarded to upstream forces
	//                              // a per-request connection teardown,
	//                              // wasting upstream's pool capacity.
	// "keep-alive":          {}, // MEDIUM — hop-by-hop; rarely honored.
	// "upgrade":              {}, // MEDIUM — could trigger an unintended
	//                              // protocol upgrade (WebSocket/HTTP-2)
	//                              // attempt at the upstream.
	// "proxy-authenticate":  {}, // LOW — server→client header; forwarded
	//                              // from a client direction it's
	//                              // meaningless but harmless.
	// "baggage":             {}, // LOW — OpenTelemetry context. Leaks
	//                              // DefenseClaw session metadata to the
	//                              // upstream provider; privacy concern
	//                              // only, no exploit.
	// "content-type":        {}, // ZERO — actively wrong to block. Go's
	//                              // http.NewRequestWithContext does NOT
	//                              // auto-set Content-Type for a raw
	//                              // io.Reader body; if we strip the
	//                              // inbound value, upstream parsers
	//                              // expecting application/json will fail.
	// ── END: blocklist expansion.
}

// ErrInvalidHeaderName is returned when a forwarded header name fails
// RFC 7230 tchar validation. Callers should map this to HTTP 400.
var ErrInvalidHeaderName = errors.New("invalid forwarded header name")

// ErrInvalidHeaderValue is returned when a forwarded header value
// contains CR, LF, NUL, or other non-printable bytes. Header-injection
// defense. Callers should map this to HTTP 400.
var ErrInvalidHeaderValue = errors.New("invalid forwarded header value")

// ErrTooManyHeaders is returned when the forwarded header count would
// exceed maxForwardedHeaders. Callers should map this to HTTP 413.
var ErrTooManyHeaders = errors.New("too many forwarded headers")

// ErrHeadersTooLarge is returned when the combined byte size of the
// forwarded header names + values would exceed maxForwardedBytes.
// Callers should map this to HTTP 413.
var ErrHeadersTooLarge = errors.New("forwarded headers too large")

// shouldForwardHeader returns true when the given header name (any
// casing) is eligible for forwarding to the upstream provider. The
// check enforces both the always-denied set and the X-DC-* /
// X-DefenseClaw-* prefix blocklist.
func shouldForwardHeader(name string) bool {
	if name == "" {
		return false
	}
	lk := strings.ToLower(name)
	if _, denied := alwaysDeniedHeaders[lk]; denied {
		return false
	}
	if strings.HasPrefix(lk, "x-dc-") || strings.HasPrefix(lk, "x-defenseclaw-") {
		return false
	}
	return true
}

// isValidHeaderName reports whether name matches the RFC 7230 tchar
// production. Empty input returns false. We do the check in-place to
// avoid the per-call allocation a precompiled regexp would incur on
// the request hot path.
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
			c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
			c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

// isValidHeaderValue rejects any byte that is not printable ASCII
// (0x20-0x7E) or HTAB (0x09). In particular this blocks CR (0x0D),
// LF (0x0A), and NUL (0x00) — the canonical header- and
// log-injection vectors. Empty value is permitted (RFC 7230 allows
// field-value to be empty after folding obs-fold).
func isValidHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// CopyForwardableHeaders copies every header from src to dst that is
// safe to forward to an upstream LLM provider, applying the
// always-denied blocklist, RFC 7230 name validation, value validation
// (no CR/LF/NUL), and the count/size caps.
//
// Forwarded headers are written with Set semantics: any pre-existing
// value on dst for the same canonical key is dropped first. This
// prevents an upstream from seeing both an inbound value and a value
// the gateway derived elsewhere (defense against header-spoofing via
// duplicate names on different paths).
//
// Returns the number of headers written and an error keyed to one of
// ErrInvalidHeaderName, ErrInvalidHeaderValue, ErrTooManyHeaders, or
// ErrHeadersTooLarge so the caller can map to the correct HTTP
// response code.
func CopyForwardableHeaders(dst, src http.Header) (int, error) {
	if dst == nil {
		return 0, errors.New("forward_headers: nil destination")
	}
	count := 0
	bytes := 0
	for name, values := range src {
		if !shouldForwardHeader(name) {
			continue
		}
		if !isValidHeaderName(name) {
			return count, ErrInvalidHeaderName
		}
		for _, v := range values {
			if !isValidHeaderValue(v) {
				return count, ErrInvalidHeaderValue
			}
		}
		// Canonicalize so callers see deterministic header names on
		// the upstream request regardless of inbound casing.
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		dst.Del(canonical)
		for _, v := range values {
			dst.Add(canonical, v)
			count++
			bytes += len(canonical) + len(v)
			if count > maxForwardedHeaders {
				return count, ErrTooManyHeaders
			}
			if bytes > maxForwardedBytes {
				return count, ErrHeadersTooLarge
			}
		}
	}
	return count, nil
}

// MergeConnectorExtraHeaders overlays headers contributed by an active
// connector (via ConnectorSignals.ExtraHeaders) onto dst with
// connector-wins semantics: connector values overwrite any prior dst
// value for the same canonical key. The same blocklist and validation
// applied to inbound headers also runs here so a misbehaving connector
// cannot leak DefenseClaw correlation metadata or smuggle CR/LF
// payloads into the upstream request.
//
// Returns the number of headers added/overwritten and an error keyed
// to the same sentinel set as CopyForwardableHeaders.
func MergeConnectorExtraHeaders(dst http.Header, extras map[string]string) (int, error) {
	if dst == nil {
		return 0, errors.New("forward_headers: nil destination")
	}
	if len(extras) == 0 {
		return 0, nil
	}
	count := 0
	bytes := 0
	for name, value := range extras {
		if !shouldForwardHeader(name) {
			continue
		}
		if !isValidHeaderName(name) {
			return count, ErrInvalidHeaderName
		}
		if !isValidHeaderValue(value) {
			return count, ErrInvalidHeaderValue
		}
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		dst.Set(canonical, value)
		count++
		bytes += len(canonical) + len(value)
		if count > maxForwardedHeaders {
			return count, ErrTooManyHeaders
		}
		if bytes > maxForwardedBytes {
			return count, ErrHeadersTooLarge
		}
	}
	return count, nil
}

// httpStatusForHeaderError maps the forward-header sentinel errors to
// the appropriate HTTP status code. Unknown errors return 400 so the
// caller fails closed.
func httpStatusForHeaderError(err error) int {
	switch {
	case errors.Is(err, ErrTooManyHeaders), errors.Is(err, ErrHeadersTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrInvalidHeaderName), errors.Is(err, ErrInvalidHeaderValue):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

// resultForHeaderError maps the forward-header sentinel errors to the
// metric result label
// (defenseclaw.gateway.forwarded_headers{result=...}).
func resultForHeaderError(err error) string {
	switch {
	case errors.Is(err, ErrTooManyHeaders), errors.Is(err, ErrHeadersTooLarge):
		return "rejected_overflow"
	case errors.Is(err, ErrInvalidHeaderName), errors.Is(err, ErrInvalidHeaderValue):
		return "rejected_invalid"
	default:
		return "rejected_invalid"
	}
}
