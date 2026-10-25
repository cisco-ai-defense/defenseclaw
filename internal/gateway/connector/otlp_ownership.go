// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Native OTLP exporter ownership is decided by the secret, never by where an
// exporter points or how its headers are spelled. Every writer that cleans up
// a DefenseClaw exporter uses this one rule: Codex and Claude Code Setup, the
// managed per-user cleanup and Verify (RemoveUserNativeOTLP and
// UserNativeOTLPResidue, which the Linux, macOS and Windows enterprise paths
// call), VerifyClean, and Doctor through its mirror.
//
// An exporter, header or env value is product-owned when it carries a
// credential this install can name (the scoped token sidecar, the tokens
// Setup was given, the bearers Claude Code's backup recorded), or a value of
// the product token shape together with DefenseClaw provenance in the same
// value: an x-defenseclaw-* marker or the scoped /otlp/<connector>/<token>
// route. Host Setup no longer exports native OTLP, so cleanup removes it and
// the credential never reaches a port DefenseClaw does not own.
//
// The token shape alone proves nothing: an operator collector may use its own
// 64-hex bearer, and a resource attribute may hold a sha256. Such a value, and
// one too deeply encoded to check, is the operator's and keeps its bytes;
// Doctor names it. Everything else is the operator's too, on any host or
// port, with or without stale x-defenseclaw-* marker headers.

// otlpProductTokenRE matches the shape of every credential DefenseClaw mints
// (EnsureOTLPPathToken, EnsureGatewayToken and the hook tokens): 32 random
// bytes as 64 lowercase hex, not part of a longer alphanumeric run.
var otlpProductTokenRE = regexp.MustCompile(`(?:^|[^0-9A-Za-z])[0-9a-f]{64}(?:[^0-9A-Za-z]|$)`)

// otlpScopedRouteRE matches the scoped route DefenseClaw writes
// (/otlp/<connector>/<token>/...), which is provenance for its token.
var otlpScopedRouteRE = regexp.MustCompile(`/otlp/[0-9a-z_-]+/[0-9a-f]{64}(?:[^0-9A-Za-z]|$)`)

// otlpBasicCredentialRE finds the credential of an HTTP Basic Authorization
// value (RFC 7617), whose user:password is base64. The scheme is
// case-insensitive.
var otlpBasicCredentialRE = regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z])basic[ \t]+([0-9A-Za-z+/_-]{4,}=*)`)

// otlpMinKnownTokenLen keeps a short configured value from matching ordinary
// text by accident.
const otlpMinKnownTokenLen = 8

// otlpMaxValueForms bounds the decoded forms checked for one string: the
// value, each percent-decode layer and each Basic credential. The work is
// linear in the value, whatever its nesting.
const otlpMaxValueForms = 16

// otlpCarriesProductCredential reports whether v (a string, or any TOML or
// JSON table or array, keys included) is product-owned under the rule above.
func otlpCarriesProductCredential(v interface{}, known []string) bool {
	var evidence otlpCredentialEvidence
	evidence.scan(v, known)
	return evidence.owned()
}

// otlpCredentialEvidence is what one value shows: a known credential, the
// product token shape and DefenseClaw provenance.
type otlpCredentialEvidence struct {
	known, shape, provenance bool
}

func (e *otlpCredentialEvidence) owned() bool {
	return e.known || e.shape && e.provenance
}

func (e *otlpCredentialEvidence) scan(v interface{}, known []string) {
	switch value := v.(type) {
	case string:
		// Forms past the bound are not checked; Doctor names such a value.
		forms, _ := otlpValueForms(value)
		for _, form := range forms {
			for _, token := range known {
				if len(token) >= otlpMinKnownTokenLen && strings.Contains(form, token) {
					e.known = true
				}
			}
			if otlpProductTokenRE.MatchString(form) {
				e.shape = true
			}
			if strings.Contains(strings.ToLower(form), "x-defenseclaw-") || otlpScopedRouteRE.MatchString(form) {
				e.provenance = true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			e.scan(key, known)
			e.scan(item, known)
		}
	case []interface{}:
		for _, item := range value {
			e.scan(item, known)
		}
	}
}

// otlpValueForms returns s and the forms a collector can recover from it:
// every percent-decode layer (header and resource lists, endpoint userinfo
// and queries may percent-encode a value) and the user:password of every
// Basic credential, at most otlpMaxValueForms of them. limited reports that
// the bound left a form unchecked. The walk is iterative, so nesting cannot
// exhaust the stack.
func otlpValueForms(s string) (forms []string, limited bool) {
	pending := []string{s}
	seen := map[string]bool{}
	for len(pending) > 0 {
		value := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[value] {
			continue
		}
		if len(forms) == otlpMaxValueForms {
			return forms, true
		}
		seen[value] = true
		forms = append(forms, value)
		if decoded := otlpPercentDecode(value); decoded != value {
			pending = append(pending, decoded)
		}
		for _, match := range otlpBasicCredentialRE.FindAllStringSubmatch(value, otlpMaxValueForms) {
			if decoded, ok := otlpBase64Decode(match[1]); ok {
				pending = append(pending, decoded)
			}
		}
	}
	return forms, false
}

// otlpBase64Decode decodes standard or URL-safe base64, padded or not.
func otlpBase64Decode(s string) (string, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(s); err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

// otlpPercentDecode decodes every valid %XX escape in s and keeps every other
// byte as is, the way Doctor's urllib.parse.unquote does.
func otlpPercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := otlpUnhex(s[i+1]); ok {
				if lo, ok := otlpUnhex(s[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func otlpUnhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// otlpKnownProductTokens returns the credentials this install can name: the
// scoped and hook tokens Setup was given and the scope's token sidecar. A
// sidecar that cannot be read (missing, or another account's on Windows) adds
// nothing; a token-shaped value then needs DefenseClaw provenance.
func otlpKnownProductTokens(opts SetupOpts, scope OTLPPathTokenScope) []string {
	known := []string{strings.TrimSpace(opts.OTLPPathToken), strings.TrimSpace(opts.APIToken)}
	if opts.DataDir != "" {
		if token, err := LoadOTLPPathToken(opts.DataDir, scope); err == nil {
			known = append(known, token)
		}
	}
	return known
}

// otlpBearerCredential returns the credential of an Authorization value that
// uses the Bearer scheme. The scheme is case-insensitive (RFC 9110 section
// 11.1) and the whitespace around it is not significant.
func otlpBearerCredential(value string) (string, bool) {
	value = strings.TrimSpace(value)
	cut := strings.IndexAny(value, " \t")
	if cut < 0 || !strings.EqualFold(value[:cut], "Bearer") {
		return "", false
	}
	credential := strings.TrimSpace(value[cut:])
	return credential, credential != ""
}
