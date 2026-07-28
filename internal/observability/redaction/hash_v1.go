// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package redaction implements value-safe observability redaction primitives.
package redaction

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"golang.org/x/text/unicode/norm"
)

const (
	hashV1Domain  = "defenseclaw-redaction-hash-v1"
	hashV1KeySize = 32
)

// HashV1ErrorCode is a value-free reason why hash-v1 could not be applied.
type HashV1ErrorCode string

const (
	HashV1ErrorInvalidUTF8       HashV1ErrorCode = "invalid_utf8"
	HashV1ErrorInvalidKey        HashV1ErrorCode = "invalid_key"
	HashV1ErrorUnsupportedClass  HashV1ErrorCode = "unsupported_class"
	HashV1ErrorUnicodeRepertoire HashV1ErrorCode = "unicode_repertoire"
	HashV1ErrorNormalization     HashV1ErrorCode = "normalization_failed"
)

// HashV1Error deliberately contains no input value, key material, or key ID.
type HashV1Error struct {
	Code HashV1ErrorCode
}

func (e *HashV1Error) Error() string {
	return "redaction hash-v1 failed: " + string(e.Code)
}

// IsHashV1Error reports whether err has the requested safe hash-v1 code.
func IsHashV1Error(err error, code HashV1ErrorCode) bool {
	var typed *HashV1Error
	return errors.As(err, &typed) && typed.Code == code
}

func hashV1Error(code HashV1ErrorCode) error {
	return &HashV1Error{Code: code}
}

// HashV1 applies the version-1, cross-language keyed correlation transform.
// It returns only the non-reversible token; normalized input is never exposed.
func HashV1(value string, fieldClass observability.FieldClass, key []byte) (string, error) {
	if !utf8.ValidString(value) {
		return "", hashV1Error(HashV1ErrorInvalidUTF8)
	}
	if len(key) != hashV1KeySize {
		return "", hashV1Error(HashV1ErrorInvalidKey)
	}
	if !observability.IsFieldClass(fieldClass) {
		return "", hashV1Error(HashV1ErrorUnsupportedClass)
	}

	normalized, err := normalizeHashV1Value(value, fieldClass)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(hashV1Domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(fieldClass))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(normalized))
	digest := mac.Sum(nil)
	keyID := hashV1KeyID(key)

	return fmt.Sprintf(
		"<hashed class=%s v=1 key=%s len=%d hmac=%s>",
		fieldClass,
		keyID,
		len(value),
		hex.EncodeToString(digest),
	), nil
}

func hashV1KeyID(key []byte) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:6])
}

func normalizeHashV1Value(value string, fieldClass observability.FieldClass) (string, error) {
	if !utf8.ValidString(value) {
		return "", hashV1Error(HashV1ErrorInvalidUTF8)
	}
	if !observability.IsFieldClass(fieldClass) {
		return "", hashV1Error(HashV1ErrorUnsupportedClass)
	}
	if !isUnicode13Repertoire(value) {
		return "", hashV1Error(HashV1ErrorUnicodeRepertoire)
	}
	value = norm.NFC.String(value)
	if fieldClass != observability.FieldClassPath {
		return value, nil
	}
	if isWindowsDrivePath(value) {
		return normalizeLexicalPath(value), nil
	}
	if hierarchicalURIPattern.MatchString(value) {
		return normalizeAbsoluteURI(value)
	}
	return normalizeLexicalPath(value), nil
}

var hierarchicalURIPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

func isWindowsDrivePath(value string) bool {
	return len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':'
}

func normalizeLexicalPath(value string) string {
	value = strings.ReplaceAll(value, `\`, "/")

	prefix := ""
	absolute := false
	uncRoot := false
	rest := value
	switch {
	case len(rest) >= 2 && rest[0] == '/' && rest[1] == '/':
		prefix = "//"
		rest = strings.TrimLeft(rest[2:], "/")
		parts := nonemptyPathSegments(rest)
		if len(parts) >= 2 && isOrdinaryPathSegment(parts[0]) && isOrdinaryPathSegment(parts[1]) {
			prefix += parts[0] + "/" + parts[1]
			rest = strings.Join(parts[2:], "/")
			absolute = true
			uncRoot = true
		}
	case strings.HasPrefix(rest, "/"):
		prefix = "/"
		absolute = true
		rest = strings.TrimLeft(rest[1:], "/")
	case len(rest) >= 2 && isASCIILetter(rest[0]) && rest[1] == ':':
		prefix = strings.ToLower(rest[:1]) + ":"
		rest = rest[2:]
		if strings.HasPrefix(rest, "/") {
			prefix += "/"
			absolute = true
			rest = strings.TrimLeft(rest, "/")
		}
	}

	segments := make([]string, 0, strings.Count(rest, "/")+1)
	for _, segment := range strings.Split(rest, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(segments) > 0 && segments[len(segments)-1] != ".." {
				segments = segments[:len(segments)-1]
			} else if !absolute {
				segments = append(segments, segment)
			}
		default:
			segments = append(segments, segment)
		}
	}

	joined := strings.Join(segments, "/")
	if prefix == "" {
		return joined
	}
	if joined == "" {
		return prefix
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + joined
	}
	if uncRoot {
		return prefix + "/" + joined
	}
	return prefix + joined
}

func nonemptyPathSegments(value string) []string {
	parts := strings.Split(value, "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func isOrdinaryPathSegment(value string) bool {
	return value != "" && value != "." && value != ".."
}

func normalizeAbsoluteURI(value string) (string, error) {
	if !isASCIIURI(value) {
		return "", hashV1Error(HashV1ErrorNormalization)
	}
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return "", hashV1Error(HashV1ErrorNormalization)
	}
	scheme := strings.ToLower(value[:colon])
	rest := value[colon+1:]
	if !strings.HasPrefix(rest, "//") {
		return "", hashV1Error(HashV1ErrorNormalization)
	}

	// A fragment is syntactically validated even though it is discarded.
	if fragmentAt := strings.IndexByte(rest, '#'); fragmentAt >= 0 {
		if _, err := normalizeURIComponent(rest[fragmentAt+1:], uriQueryFragment); err != nil {
			return "", err
		}
		rest = rest[:fragmentAt]
	}

	query := ""
	hasQuery := false
	if queryAt := strings.IndexByte(rest, '?'); queryAt >= 0 {
		hasQuery = true
		var err error
		query, err = normalizeURIComponent(rest[queryAt+1:], uriQueryFragment)
		if err != nil {
			return "", err
		}
		rest = rest[:queryAt]
	}

	authority := ""
	hasAuthority := strings.HasPrefix(rest, "//")
	path := rest
	if hasAuthority {
		authorityEnd := strings.IndexByte(rest[2:], '/')
		if authorityEnd < 0 {
			authority = rest[2:]
			path = ""
		} else {
			authorityEnd += 2
			authority = rest[2:authorityEnd]
			path = rest[authorityEnd:]
		}
		var err error
		authority, err = normalizeURIAuthority(authority, scheme)
		if err != nil {
			return "", err
		}
	}

	path, err := normalizeURIComponent(path, uriPath)
	if err != nil {
		return "", err
	}
	path = removeURIDotSegments(path)

	var result strings.Builder
	result.Grow(len(value))
	result.WriteString(scheme)
	result.WriteByte(':')
	if hasAuthority {
		result.WriteString("//")
		result.WriteString(authority)
	}
	result.WriteString(path)
	if hasQuery {
		result.WriteByte('?')
		result.WriteString(query)
	}
	return result.String(), nil
}

type uriComponent int

const (
	uriPath uriComponent = iota
	uriQueryFragment
	uriUserInfo
	uriRegName
)

func normalizeURIComponent(value string, component uriComponent) (string, error) {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '%' {
			if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
				return "", hashV1Error(HashV1ErrorNormalization)
			}
			decoded := fromHex(value[index+1])<<4 | fromHex(value[index+2])
			if isURIUnreserved(decoded) {
				result.WriteByte(decoded)
			} else {
				result.WriteByte('%')
				result.WriteByte(toUpperHex(decoded >> 4))
				result.WriteByte(toUpperHex(decoded & 0x0f))
			}
			index += 2
			continue
		}
		if !isAllowedURICharacter(character, component) {
			return "", hashV1Error(HashV1ErrorNormalization)
		}
		result.WriteByte(character)
	}
	return result.String(), nil
}

func normalizeURIAuthority(authority, scheme string) (string, error) {
	userinfo := ""
	hostport := authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		var err error
		userinfo, err = normalizeURIComponent(authority[:at], uriUserInfo)
		if err != nil {
			return "", err
		}
		userinfo += "@"
		hostport = authority[at+1:]
	}

	host := ""
	port := ""
	explicitPort := false
	bracketed := false
	if strings.HasPrefix(hostport, "[") {
		closeAt := strings.IndexByte(hostport, ']')
		if closeAt < 0 {
			return "", hashV1Error(HashV1ErrorNormalization)
		}
		bracketed = true
		host = hostport[1:closeAt]
		remainder := hostport[closeAt+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") {
				return "", hashV1Error(HashV1ErrorNormalization)
			}
			explicitPort = true
			port = remainder[1:]
		}
		if !isValidIPLiteral(host) {
			return "", hashV1Error(HashV1ErrorNormalization)
		}
		host = normalizeURIHostCase(host)
	} else {
		if strings.Count(hostport, ":") > 1 {
			return "", hashV1Error(HashV1ErrorNormalization)
		}
		if colonAt := strings.LastIndexByte(hostport, ':'); colonAt >= 0 {
			host = hostport[:colonAt]
			explicitPort = true
			port = hostport[colonAt+1:]
		} else {
			host = hostport
		}
		var err error
		host, err = normalizeURIComponent(host, uriRegName)
		if err != nil {
			return "", err
		}
		host = normalizeURIHostCase(host)
	}
	if host == "" || (explicitPort && port == "") {
		return "", hashV1Error(HashV1ErrorNormalization)
	}

	if port != "" {
		for index := range len(port) {
			if port[index] < '0' || port[index] > '9' {
				return "", hashV1Error(HashV1ErrorNormalization)
			}
		}
		if isDefaultPort(scheme, port) {
			port = ""
		}
	}

	if bracketed {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return userinfo + host, nil
}

func removeURIDotSegments(path string) string {
	input := path
	output := make([]byte, 0, len(path))
	slashPositions := make([]int, 0, strings.Count(path, "/"))
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output, slashPositions = removeLastURISegment(output, slashPositions)
		case input == "/..":
			input = "/"
			output, slashPositions = removeLastURISegment(output, slashPositions)
		case input == "." || input == "..":
			input = ""
		default:
			length := firstURISegmentLength(input)
			if input[0] == '/' {
				slashPositions = append(slashPositions, len(output))
			}
			output = append(output, input[:length]...)
			input = input[length:]
		}
	}
	return string(output)
}

func firstURISegmentLength(input string) int {
	start := 0
	if strings.HasPrefix(input, "/") {
		start = 1
	}
	if slashAt := strings.IndexByte(input[start:], '/'); slashAt >= 0 {
		return start + slashAt
	}
	return len(input)
}

func removeLastURISegment(output []byte, slashPositions []int) ([]byte, []int) {
	if len(slashPositions) > 0 {
		last := len(slashPositions) - 1
		return output[:slashPositions[last]], slashPositions[:last]
	}
	return output[:0], slashPositions
}

func isASCIIURI(value string) bool {
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '\\' {
			return false
		}
	}
	return true
}

func isAllowedURICharacter(character byte, component uriComponent) bool {
	if isURIUnreserved(character) || strings.ContainsRune("!$&'()*+,;=", rune(character)) {
		return true
	}
	switch component {
	case uriPath:
		return character == '/' || character == ':' || character == '@'
	case uriQueryFragment:
		return character == '/' || character == '?' || character == ':' || character == '@'
	case uriUserInfo:
		return character == ':'
	case uriRegName:
		return false
	default:
		return false
	}
}

func isValidIPLiteral(value string) bool {
	if value == "" || strings.Contains(value, "%") {
		return false
	}
	if value[0] == 'v' || value[0] == 'V' {
		dotAt := strings.IndexByte(value, '.')
		if dotAt < 2 || dotAt == len(value)-1 {
			return false
		}
		for index := 1; index < dotAt; index++ {
			if !isHex(value[index]) {
				return false
			}
		}
		for index := dotAt + 1; index < len(value); index++ {
			character := value[index]
			if !isURIUnreserved(character) && !strings.ContainsRune("!$&'()*+,;=:", rune(character)) {
				return false
			}
		}
		return true
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is6()
}

func isDefaultPort(scheme, port string) bool {
	canonicalPort := strings.TrimLeft(port, "0")
	if canonicalPort == "" {
		canonicalPort = "0"
	}
	switch scheme {
	case "http":
		return canonicalPort == "80"
	case "https":
		return canonicalPort == "443"
	default:
		return false
	}
}

func normalizeURIHostCase(host string) string {
	var result strings.Builder
	result.Grow(len(host))
	for index := 0; index < len(host); index++ {
		character := host[index]
		if character == '%' && index+2 < len(host) && isHex(host[index+1]) && isHex(host[index+2]) {
			decoded := fromHex(host[index+1])<<4 | fromHex(host[index+2])
			if isURIUnreserved(decoded) {
				if decoded >= 'A' && decoded <= 'Z' {
					decoded += 'a' - 'A'
				}
				result.WriteByte(decoded)
			} else {
				result.WriteByte('%')
				result.WriteByte(toUpperHex(decoded >> 4))
				result.WriteByte(toUpperHex(decoded & 0x0f))
			}
			index += 2
			continue
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		result.WriteByte(character)
	}
	return result.String()
}

func isURIUnreserved(character byte) bool {
	return isASCIILetter(character) || (character >= '0' && character <= '9') ||
		character == '-' || character == '.' || character == '_' || character == '~'
}

func isASCIILetter(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func isHex(character byte) bool {
	return (character >= '0' && character <= '9') ||
		(character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}

func fromHex(character byte) byte {
	if character >= '0' && character <= '9' {
		return character - '0'
	}
	if character >= 'a' && character <= 'f' {
		return character - 'a' + 10
	}
	return character - 'A' + 10
}

func toUpperHex(value byte) byte {
	if value < 10 {
		return '0' + value
	}
	return 'A' + value - 10
}
