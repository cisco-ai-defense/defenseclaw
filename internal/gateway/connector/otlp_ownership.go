// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
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
// An exporter, header or env value that carries a DefenseClaw credential is
// product-owned. Host Setup no longer exports native OTLP, so cleanup removes
// it and the credential never reaches a port DefenseClaw does not own.
// Everything else is the operator's and keeps its bytes, on any host or port,
// with or without stale x-defenseclaw-* marker headers.

// otlpProductTokenRE matches the shape of every credential DefenseClaw mints
// (EnsureOTLPPathToken, EnsureGatewayToken and the hook tokens): 32 random
// bytes as 64 lowercase hex, not part of a longer alphanumeric run. The shape
// still proves ownership when the issuing sidecar is missing or unreadable.
var otlpProductTokenRE = regexp.MustCompile(`(?:^|[^0-9A-Za-z])[0-9a-f]{64}(?:[^0-9A-Za-z]|$)`)

// otlpMinKnownTokenLen keeps a short configured value from matching ordinary
// text by accident.
const otlpMinKnownTokenLen = 8

// otlpCarriesProductCredential reports whether v (a string, or any TOML or
// JSON table or array, keys included) contains one of the known credentials or
// a value of the product token shape.
func otlpCarriesProductCredential(v interface{}, known []string) bool {
	switch value := v.(type) {
	case string:
		// OTLP header and resource lists, endpoint userinfo and queries may
		// percent-encode a value ("Bearer%20..."). One stray "%" elsewhere in
		// the string must not hide it, so the decode is lenient.
		if decoded := otlpPercentDecode(value); decoded != value &&
			otlpCarriesProductCredential(decoded, known) {
			return true
		}
		if otlpProductTokenRE.MatchString(value) {
			return true
		}
		for _, token := range known {
			if len(token) >= otlpMinKnownTokenLen && strings.Contains(value, token) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			if otlpCarriesProductCredential(key, known) || otlpCarriesProductCredential(item, known) {
				return true
			}
		}
	case []interface{}:
		for _, item := range value {
			if otlpCarriesProductCredential(item, known) {
				return true
			}
		}
	}
	return false
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
// nothing; the token shape still proves ownership.
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
