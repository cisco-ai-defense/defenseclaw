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
// credential this install can name: the scoped token sidecar, the tokens
// Setup was given, or the bearers Claude Code's backup recorded. Host Setup no
// longer exports native OTLP, so cleanup removes it and the credential never
// reaches a port DefenseClaw does not own.
//
// Nothing else proves ownership. A value that only looks like a DefenseClaw
// token (an operator collector's own 64-hex bearer, a sha256 resource
// attribute), with or without stale x-defenseclaw-* markers, is the
// operator's and keeps its bytes on any host or port: a false delete loses
// operator data. So is a value encoded past the decode budget below; Doctor
// names it.

// otlpBasicCredentialRE finds the credential of an HTTP Basic Authorization
// value (RFC 7617), whose user:password is base64. The scheme is
// case-insensitive.
var otlpBasicCredentialRE = regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z])basic[ \t]+([0-9A-Za-z+/_-]{4,}=*)`)

// otlpMinKnownTokenLen keeps a short configured value from matching ordinary
// text by accident.
const otlpMinKnownTokenLen = 8

// The decode budget for one string. A collector recovers a credential from a
// header or resource list value (one percent-decode layer), a URL or a value
// encoded once more inside it (a second layer), and an HTTP Basic credential
// (base64, once). A value that needs more than that, or is larger than
// otlpMaxDecodeBytes, is not decoded further.
const (
	otlpMaxPercentLayers    = 2
	otlpMaxBasicCredentials = 4
	otlpMaxDecodeBytes      = 64 << 10
)

// otlpCarriesProductCredential reports whether v (a string, or any TOML or
// JSON table or array, keys included) is product-owned under the rule above.
func otlpCarriesProductCredential(v interface{}, known []string) bool {
	switch value := v.(type) {
	case string:
		// A value past the decode budget is checked only in the forms the
		// budget reached; Doctor names it.
		forms, _ := otlpValueForms(value)
		for _, form := range forms {
			for _, token := range known {
				if len(token) >= otlpMinKnownTokenLen && strings.Contains(form, token) {
					return true
				}
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

// otlpValueForms returns s and the forms a collector can recover from it
// within the decode budget: up to otlpMaxPercentLayers percent-decode layers
// (header and resource lists, endpoint userinfo and queries percent-encode a
// value) and the base64-decoded user:password of each Basic credential in
// those. limited reports a value the budget did not finish: larger than
// otlpMaxDecodeBytes, a further percent layer, more Basic credentials, or a
// Basic credential that is itself encoded again. At most
// (1+otlpMaxPercentLayers)*(1+otlpMaxBasicCredentials) forms are returned,
// each no longer than s, so the work is linear in s whatever its nesting.
func otlpValueForms(s string) (forms []string, limited bool) {
	forms = []string{s}
	if len(s) > otlpMaxDecodeBytes {
		return forms, strings.Contains(s, "%") || otlpBasicCredentialRE.MatchString(s)
	}
	layer := s
	for range otlpMaxPercentLayers {
		decoded := otlpPercentDecode(layer)
		if decoded == layer {
			break
		}
		forms = append(forms, decoded)
		layer = decoded
	}
	if otlpPercentDecode(layer) != layer {
		limited = true
	}
	percentForms := len(forms)
	for _, form := range forms[:percentForms] {
		matches := otlpBasicCredentialRE.FindAllStringSubmatch(form, otlpMaxBasicCredentials+1)
		if len(matches) > otlpMaxBasicCredentials {
			limited = true
			matches = matches[:otlpMaxBasicCredentials]
		}
		for _, match := range matches {
			decoded, ok := otlpBase64Decode(match[1])
			if !ok {
				continue
			}
			forms = append(forms, decoded)
			if otlpPercentDecode(decoded) != decoded || otlpBasicCredentialRE.MatchString(decoded) {
				limited = true
			}
		}
	}
	return forms, limited
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
// nothing, and a value then needs another known credential to be the
// product's.
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
