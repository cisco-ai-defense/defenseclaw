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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	toolValueLineageDomain          = "defenseclaw/tool-value-lineage/v1"
	toolValueLineageKeyBytes        = sha256.Size
	toolValueLineageMaxInputBytes   = 64 * 1024
	toolValueLineageMaxTokenBytes   = 4 * 1024
	toolValueLineageMaxTokenTotal   = 32 * 1024
	toolValueLineageMinTokenBytes   = 12
	toolValueLineageMaxTokens       = 16
	toolValueLineageMaxJSONDepth    = 4
	toolValueLineageMaxJSONElements = 256
)

// toolValueLineageDigest is the only value returned across this helper
// boundary. Source text and outbound payloads remain request-scoped and are
// never retained in a projection object.
type toolValueLineageDigest [sha256.Size]byte

// toolValueLineageSourceKind is selected by a future trusted read-path
// classifier. Content is never allowed to select a more permissive grammar.
type toolValueLineageSourceKind uint8

const (
	toolValueLineageSourceEnv toolValueLineageSourceKind = iota + 1
	toolValueLineageSourceJSON
	toolValueLineageSourcePEM
	toolValueLineageSourceSingleToken
)

// toolValueLineageSourceDigests projects a successful sensitive-read result
// into bounded keyed tokens. It is pure and deliberately has no logging,
// persistence, or lifecycle behavior.
func toolValueLineageSourceDigests(
	key [toolValueLineageKeyBytes]byte,
	kind toolValueLineageSourceKind,
	result []byte,
) ([]toolValueLineageDigest, bool) {
	if !toolValueLineageInputValid(result) {
		return nil, false
	}

	var tokens []string
	var ok bool
	switch kind {
	case toolValueLineageSourceEnv:
		tokens, ok = toolValueLineageEnvTokens(string(result))
	case toolValueLineageSourceJSON:
		tokens, ok = toolValueLineageJSONTokens(result, true)
	case toolValueLineageSourcePEM:
		tokens, ok = toolValueLineagePEMTokens(result)
	case toolValueLineageSourceSingleToken:
		tokens, ok = toolValueLineageSingleToken(result)
	default:
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return toolValueLineageDigestTokens(key, tokens)
}

// toolValueLineageCurlPayloadDigests projects only literal request-body bytes
// from a fully parsed curl CommandFact. Deterministic or dynamic transforms,
// multipart forms, GET-query conversion, file/stdin sources, and shell
// expansion are outside this first exact-value slice.
func toolValueLineageCurlPayloadDigests(
	key [toolValueLineageKeyBytes]byte,
	command actionfacts.CommandFact,
) ([]toolValueLineageDigest, bool) {
	if !command.ArgvComplete || len(command.Argv) == 0 ||
		len(command.Arguments) != len(command.Argv) ||
		toolValueLineageCurlHasUnsupportedMode(command) {
		return nil, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed {
			return nil, false
		}
	}

	payloads := actionfacts.StaticCurlUploadPayloads(command)
	if len(payloads) == 0 || len(payloads) > toolValueLineageMaxTokens {
		return nil, false
	}
	var tokens []string
	for _, payload := range payloads {
		projected, ok := toolValueLineageOutboundPayloadTokens([]byte(payload))
		if !ok {
			return nil, false
		}
		tokens = append(tokens, projected...)
		if len(tokens) > toolValueLineageMaxTokens {
			return nil, false
		}
	}
	return toolValueLineageDigestTokens(key, tokens)
}

// toolValueLineageStructuredBodyDigests accepts only closed HTTP upload
// schemas. Destination trust remains the responsibility of the future runtime
// integration; this helper neither classifies nor special-cases localhost.
func toolValueLineageStructuredBodyDigests(
	key [toolValueLineageKeyBytes]byte,
	tool string,
	args json.RawMessage,
) ([]toolValueLineageDigest, bool) {
	if !toolValueLineageInputValid(args) {
		return nil, false
	}
	requestKind, ok := toolValueLineageStructuredRequestKind(tool)
	if !ok {
		return nil, false
	}
	decoded, ok := toolValueLineageDecodeJSON(args)
	if !ok {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}

	allowed := map[string]bool{
		"url": true, "uri": true, "endpoint": true,
		"body": true, "data": true, "payload": true, "content": true,
		"method": true, "headers": true,
	}
	for field := range object {
		if !allowed[field] {
			return nil, false
		}
	}

	destination, ok := toolValueLineageSingleAliasString(object, "url", "uri", "endpoint")
	if !ok || !toolValueLineageHTTPURL(destination) {
		return nil, false
	}
	body, ok := toolValueLineageSingleAliasValue(object, "body", "data", "payload", "content")
	if !ok {
		return nil, false
	}
	if headers, present := object["headers"]; present {
		if _, ok := headers.(map[string]any); !ok {
			return nil, false
		}
	}

	method, methodPresent := object["method"]
	if methodPresent {
		methodString, ok := method.(string)
		if !ok || strings.TrimSpace(methodString) != methodString {
			return nil, false
		}
		methodString = strings.ToUpper(methodString)
		if requestKind == toolValueLineageRequestPOST {
			if methodString != "POST" {
				return nil, false
			}
		} else if methodString != "POST" && methodString != "PUT" && methodString != "PATCH" {
			return nil, false
		}
	} else if requestKind == toolValueLineageRequestMethodRequired {
		return nil, false
	}

	var tokens []string
	switch value := body.(type) {
	case string:
		tokens, ok = toolValueLineageOutboundPayloadTokens([]byte(value))
	case map[string]any, []any:
		tokens, ok = toolValueLineageJSONStringLeaves(value)
	default:
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return toolValueLineageDigestTokens(key, tokens)
}

type toolValueLineageRequestKind uint8

const (
	toolValueLineageRequestPOST toolValueLineageRequestKind = iota + 1
	toolValueLineageRequestMethodRequired
)

func toolValueLineageStructuredRequestKind(tool string) (toolValueLineageRequestKind, bool) {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return 0, false
	}
	switch strings.ToLower(tool) {
	case "httppost", "http_post", "http-post", "http.post",
		"webupload", "web_upload", "web-upload", "web.upload":
		return toolValueLineageRequestPOST, true
	case "httprequest", "http_request", "http-request", "http.request":
		return toolValueLineageRequestMethodRequired, true
	default:
		return 0, false
	}
}

func toolValueLineageCurlHasUnsupportedMode(command actionfacts.CommandFact) bool {
	for _, argument := range command.Argv[1:] {
		lower := strings.ToLower(argument)
		switch {
		case lower == "--get", strings.HasPrefix(lower, "--get="),
			lower == "--form", strings.HasPrefix(lower, "--form="),
			lower == "--form-string", strings.HasPrefix(lower, "--form-string="),
			lower == "--data-urlencode", strings.HasPrefix(lower, "--data-urlencode="),
			lower == "--config", strings.HasPrefix(lower, "--config="),
			lower == "--upload-file", strings.HasPrefix(lower, "--upload-file="):
			return true
		case strings.HasPrefix(lower, "-f"), strings.HasPrefix(lower, "-g"),
			strings.HasPrefix(lower, "-k"),
			strings.HasPrefix(lower, "-t"):
			// These short options are multipart, config, and file-upload modes.
			// Reject joined forms as well as standalone forms.
			return true
		}
	}
	return false
}

func toolValueLineageOutboundPayloadTokens(payload []byte) ([]string, bool) {
	if !toolValueLineageInputValid(payload) {
		return nil, false
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return toolValueLineageJSONTokens(trimmed, false)
	}
	if toolValueLineageLooksLikePrivatePEM(trimmed) {
		return toolValueLineagePEMTokens(trimmed)
	}
	text := string(payload)
	if strings.ContainsAny(text, "\r\n") {
		return toolValueLineageEnvTokens(text)
	}
	if strings.Contains(text, "=") {
		return toolValueLineageFormTokens(text)
	}
	return toolValueLineageSingleToken(payload)
}

func toolValueLineageEnvTokens(content string) ([]string, bool) {
	if content == "" || len(content) > toolValueLineageMaxInputBytes ||
		!utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return nil, false
	}
	seen := make(map[string]struct{})
	var tokens []string
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		separator := strings.IndexByte(line, '=')
		if separator < 1 {
			return nil, false
		}
		name, value := line[:separator], line[separator+1:]
		if !toolValueLineageEnvName(name) || value == "" {
			return nil, false
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, false
		}
		seen[name] = struct{}{}
		if value[0] == '\'' || value[0] == '"' {
			quote := value[0]
			if len(value) < 2 || value[len(value)-1] != quote ||
				strings.ContainsRune(value[1:len(value)-1], rune(quote)) ||
				strings.ContainsRune(value[1:len(value)-1], '\\') {
				return nil, false
			}
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "$`") {
			// Dotenv expansion semantics vary between consumers. Treat expansion
			// markers as unresolved rather than guessing whether they are literal.
			return nil, false
		}
		tokens = append(tokens, value)
		if len(tokens) > toolValueLineageMaxTokens {
			return nil, false
		}
	}
	return tokens, len(tokens) != 0
}

func toolValueLineageEnvName(value string) bool {
	if value == "" || value[0] != '_' && (value[0] < 'A' || value[0] > 'Z') &&
		(value[0] < 'a' || value[0] > 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character != '_' && (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func toolValueLineageJSONTokens(raw []byte, sensitiveOnly bool) ([]string, bool) {
	decoded, ok := toolValueLineageDecodeJSON(raw)
	if !ok {
		return nil, false
	}
	if sensitiveOnly {
		if _, object := decoded.(map[string]any); !object {
			return nil, false
		}
		return toolValueLineageSensitiveJSONStrings(decoded)
	}
	return toolValueLineageJSONStringLeaves(decoded)
}

func toolValueLineageSensitiveJSONStrings(value any) ([]string, bool) {
	var tokens []string
	var walk func(any, int) bool
	walk = func(current any, depth int) bool {
		if depth > toolValueLineageMaxJSONDepth {
			return false
		}
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		for key, child := range object {
			if text, scalar := child.(string); scalar && toolValueLineageSensitiveJSONKey(key) {
				tokens = append(tokens, text)
				if len(tokens) > toolValueLineageMaxTokens {
					return false
				}
				continue
			}
			switch nested := child.(type) {
			case map[string]any:
				if !walk(nested, depth+1) {
					return false
				}
			case []any:
				// Arrays introduce ordering and repeated-key ambiguity for this
				// first source grammar.
				return false
			case string, json.Number, bool, nil:
			default:
				return false
			}
		}
		return true
	}
	if !walk(value, 0) || len(tokens) == 0 {
		return nil, false
	}
	return tokens, true
}

func toolValueLineageSensitiveJSONKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch normalized {
	case "password", "passwd", "token", "secret", "credential", "credentials",
		"api_key", "access_key", "secret_key", "private_key", "client_secret":
		return true
	default:
		return strings.HasSuffix(normalized, "_password") ||
			strings.HasSuffix(normalized, "_token") ||
			strings.HasSuffix(normalized, "_secret") ||
			strings.HasSuffix(normalized, "_credential") ||
			strings.HasSuffix(normalized, "_key")
	}
}

func toolValueLineageJSONStringLeaves(value any) ([]string, bool) {
	var tokens []string
	var walk func(any, int) bool
	walk = func(current any, depth int) bool {
		if depth > toolValueLineageMaxJSONDepth {
			return false
		}
		switch typed := current.(type) {
		case string:
			tokens = append(tokens, typed)
			return len(tokens) <= toolValueLineageMaxTokens
		case map[string]any:
			for _, child := range typed {
				if !walk(child, depth+1) {
					return false
				}
			}
			return true
		case []any:
			for _, child := range typed {
				if !walk(child, depth+1) {
					return false
				}
			}
			return true
		case json.Number, bool, nil:
			return true
		default:
			return false
		}
	}
	if !walk(value, 0) || len(tokens) == 0 {
		return nil, false
	}
	return tokens, true
}

func toolValueLineagePEMTokens(content []byte) ([]string, bool) {
	trimmed := bytes.TrimSpace(content)
	if !toolValueLineageInputValid(trimmed) ||
		!toolValueLineageLooksLikePrivatePEM(trimmed) {
		return nil, false
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, false
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY":
	default:
		return nil, false
	}
	return []string{string(trimmed)}, true
}

func toolValueLineageLooksLikePrivatePEM(value []byte) bool {
	for _, label := range []string{
		"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY",
	} {
		if bytes.HasPrefix(value, []byte("-----BEGIN "+label+"-----")) {
			return true
		}
	}
	return false
}

func toolValueLineageSingleToken(content []byte) ([]string, bool) {
	value := content
	if bytes.HasSuffix(value, []byte("\r\n")) {
		value = value[:len(value)-2]
	} else if bytes.HasSuffix(value, []byte("\n")) {
		value = value[:len(value)-1]
	}
	if len(value) == 0 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return nil, false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) {
			return nil, false
		}
	}
	return []string{string(value)}, true
}

func toolValueLineageFormTokens(value string) ([]string, bool) {
	// Percent and plus processing changes bytes. This exact slice accepts only
	// already-literal form values and leaves transformed forms unsupported.
	if strings.ContainsAny(value, "%+") {
		return nil, false
	}
	seen := make(map[string]struct{})
	var tokens []string
	for _, field := range strings.Split(value, "&") {
		if strings.Count(field, "=") != 1 {
			return nil, false
		}
		parts := strings.SplitN(field, "=", 2)
		if !toolValueLineageFormName(parts[0]) || parts[1] == "" {
			return nil, false
		}
		if _, duplicate := seen[parts[0]]; duplicate {
			return nil, false
		}
		seen[parts[0]] = struct{}{}
		tokens = append(tokens, parts[1])
		if len(tokens) > toolValueLineageMaxTokens {
			return nil, false
		}
	}
	return tokens, len(tokens) != 0
}

func toolValueLineageFormName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("_.-", character) {
			continue
		}
		return false
	}
	return true
}

func toolValueLineageDigestTokens(
	key [toolValueLineageKeyBytes]byte,
	tokens []string,
) ([]toolValueLineageDigest, bool) {
	if toolValueLineageZeroKey(key) || len(tokens) == 0 ||
		len(tokens) > toolValueLineageMaxTokens {
		return nil, false
	}
	unique := make(map[string]struct{}, len(tokens))
	total := 0
	for _, token := range tokens {
		length := len(token)
		if length == 0 || length < toolValueLineageMinTokenBytes {
			continue
		}
		if length > toolValueLineageMaxTokenBytes || !utf8.ValidString(token) ||
			strings.ContainsRune(token, 0) {
			return nil, false
		}
		total += length
		if total > toolValueLineageMaxTokenTotal {
			return nil, false
		}
		unique[token] = struct{}{}
	}
	if len(unique) == 0 || len(unique) > toolValueLineageMaxTokens {
		return nil, false
	}

	digests := make([]toolValueLineageDigest, 0, len(unique))
	for token := range unique {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(toolValueLineageDomain))
		_, _ = mac.Write([]byte{0})
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(token)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(token))
		var digest toolValueLineageDigest
		copy(digest[:], mac.Sum(nil))
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool {
		return bytes.Compare(digests[i][:], digests[j][:]) < 0
	})
	return digests, true
}

func toolValueLineageZeroKey(key [toolValueLineageKeyBytes]byte) bool {
	var combined byte
	for _, value := range key {
		combined |= value
	}
	return combined == 0
}

func toolValueLineageInputValid(value []byte) bool {
	return len(value) != 0 && len(value) <= toolValueLineageMaxInputBytes &&
		utf8.Valid(value) && bytes.IndexByte(value, 0) < 0
}

func toolValueLineageSingleAliasString(object map[string]any, names ...string) (string, bool) {
	value, ok := toolValueLineageSingleAliasValue(object, names...)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func toolValueLineageSingleAliasValue(object map[string]any, names ...string) (any, bool) {
	var selected any
	found := false
	for _, name := range names {
		value, present := object[name]
		if !present {
			continue
		}
		if found {
			return nil, false
		}
		selected, found = value, true
	}
	return selected, found
}

func toolValueLineageHTTPURL(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Hostname() != ""
}

func toolValueLineageDecodeJSON(raw []byte) (any, bool) {
	if !toolValueLineageInputValid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	elements := 0
	value, err := toolValueLineageDecodeJSONValue(decoder, 0, &elements)
	if err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return value, true
}

func toolValueLineageDecodeJSONValue(
	decoder *json.Decoder,
	depth int,
	elements *int,
) (any, error) {
	if depth > toolValueLineageMaxJSONDepth {
		return nil, errors.New("tool value lineage JSON depth exceeded")
	}
	*elements = *elements + 1
	if *elements > toolValueLineageMaxJSONElements {
		return nil, errors.New("tool value lineage JSON element limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		switch token.(type) {
		case string, json.Number, bool, nil:
			return token, nil
		default:
			return nil, errors.New("tool value lineage unsupported JSON scalar")
		}
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok || key == "" || strings.ContainsRune(key, 0) {
				return nil, errors.New("tool value lineage invalid JSON key")
			}
			folded := strings.ToLower(key)
			if _, duplicate := seen[folded]; duplicate {
				return nil, errors.New("tool value lineage duplicate JSON key")
			}
			seen[folded] = struct{}{}
			child, err := toolValueLineageDecodeJSONValue(decoder, depth+1, elements)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("tool value lineage invalid JSON object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			child, err := toolValueLineageDecodeJSONValue(decoder, depth+1, elements)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("tool value lineage invalid JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("tool value lineage invalid JSON delimiter")
	}
}
