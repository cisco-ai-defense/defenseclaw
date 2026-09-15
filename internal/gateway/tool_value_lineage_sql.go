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
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const toolValueLineageSQLSSNDomain = "defenseclaw/tool-value-lineage/sql-ssn/v1"

// toolValueLineageSQLRowsetDigests projects only reviewed sensitive columns
// from a bounded, flat SQL rowset result. The table class comes from an exact
// ActionFact; result content cannot select a broader extraction grammar.
//
// Supported envelopes are strict JSON arrays of flat objects and the exact
// Python repr shape emitted by the public SQLite MCPHunt connector: a list of
// flat dictionaries with single-quoted keys/strings plus numeric and None
// scalars. This helper does not execute or generally deserialize Python.
func toolValueLineageSQLRowsetDigests(
	key [toolValueLineageKeyBytes]byte,
	table actionfacts.SensitiveSQLTableClass,
	result []byte,
) ([]toolValueLineageDigest, bool) {
	if toolValueLineageZeroKey(key) || !toolValueLineageInputValid(result) {
		return nil, false
	}
	rows, ok := toolValueLineageSQLJSONRows(result)
	if !ok {
		rows, ok = toolValueLineageSQLPythonRows(result)
	}
	if !ok || len(rows) == 0 || len(rows) > toolValueLineageMaxJSONElements {
		return nil, false
	}
	tokens, ssns, ok := toolValueLineageSQLSensitiveValues(table, rows)
	if !ok {
		return nil, false
	}
	return toolValueLineageSQLDigestSets(key, tokens, ssns)
}

// toolValueLineageStructuredPersistenceDigests revalidates the closed
// ActionFacts persistence schema before inspecting literal sink fields. It
// returns keyed digests only; paths, entity identities, observations, and
// content remain request-scoped and are never returned or retained.
func toolValueLineageStructuredPersistenceDigests(
	key [toolValueLineageKeyBytes]byte,
	input actionfacts.Input,
) ([]toolValueLineageDigest, bool) {
	if toolValueLineageZeroKey(key) || !toolValueLineageInputValid(input.Args) {
		return nil, false
	}
	if len(actionfacts.ExactStructuredLiteralPersistences(actionfacts.Analyze(input))) == 0 {
		return nil, false
	}
	decoded, ok := toolValueLineageDecodeJSON(input.Args)
	if !ok {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}

	var literals []string
	switch input.Tool {
	case "write_file":
		if len(object) != 2 {
			return nil, false
		}
		content, contentOK := object["content"].(string)
		if _, pathOK := object["path"].(string); !contentOK || !pathOK {
			return nil, false
		}
		literals = []string{content}
	case "create_entities":
		if len(object) != 1 {
			return nil, false
		}
		entities, entitiesOK := object["entities"].([]any)
		if !entitiesOK || len(entities) == 0 || len(entities) > toolValueLineageMaxTokens {
			return nil, false
		}
		for _, rawEntity := range entities {
			entity, entityOK := rawEntity.(map[string]any)
			if !entityOK || len(entity) != 3 {
				return nil, false
			}
			if _, nameOK := entity["name"].(string); !nameOK {
				return nil, false
			}
			if _, typeOK := entity["entityType"].(string); !typeOK {
				return nil, false
			}
			observations, observationsOK := entity["observations"].([]any)
			if !observationsOK || len(observations) == 0 ||
				len(observations) > toolValueLineageMaxTokens {
				return nil, false
			}
			for _, rawObservation := range observations {
				observation, observationOK := rawObservation.(string)
				if !observationOK {
					return nil, false
				}
				literals = append(literals, observation)
				if len(literals) > toolValueLineageMaxJSONElements {
					return nil, false
				}
			}
		}
	default:
		return nil, false
	}

	var tokens, ssns []string
	for _, literal := range literals {
		projected, projectedSSNs, projectedOK := toolValueLineageSQLSinkLiteralTokens(literal)
		if !projectedOK {
			return nil, false
		}
		tokens = append(tokens, projected...)
		ssns = append(ssns, projectedSSNs...)
		if len(tokens)+len(ssns) > toolValueLineageMaxTokens {
			return nil, false
		}
	}
	return toolValueLineageSQLDigestSets(key, tokens, ssns)
}

func toolValueLineageSQLJSONRows(raw []byte) ([]map[string]any, bool) {
	decoded, ok := toolValueLineageDecodeJSON(raw)
	if !ok {
		return nil, false
	}
	array, ok := decoded.([]any)
	if !ok || len(array) == 0 || len(array) > toolValueLineageMaxJSONElements {
		return nil, false
	}
	rows := make([]map[string]any, 0, len(array))
	for _, value := range array {
		row, ok := value.(map[string]any)
		if !ok || len(row) == 0 || len(row) > toolValueLineageMaxJSONElements {
			return nil, false
		}
		for _, scalar := range row {
			switch scalar.(type) {
			case string, json.Number, bool, nil:
			default:
				return nil, false
			}
		}
		rows = append(rows, row)
	}
	return rows, true
}

type toolValueLineageSQLPythonParser struct {
	raw      []byte
	position int
	elements int
}

func toolValueLineageSQLPythonRows(raw []byte) ([]map[string]any, bool) {
	if !toolValueLineageInputValid(raw) {
		return nil, false
	}
	parser := toolValueLineageSQLPythonParser{raw: raw}
	rows, ok := parser.parseRows()
	if !ok || parser.position != len(raw) {
		return nil, false
	}
	return rows, true
}

func (parser *toolValueLineageSQLPythonParser) parseRows() ([]map[string]any, bool) {
	parser.skipSpace()
	if !parser.take('[') {
		return nil, false
	}
	parser.skipSpace()
	if parser.take(']') {
		return nil, false
	}
	var rows []map[string]any
	for {
		row, ok := parser.parseRow()
		if !ok {
			return nil, false
		}
		rows = append(rows, row)
		if len(rows) > toolValueLineageMaxJSONElements {
			return nil, false
		}
		parser.skipSpace()
		if parser.take(']') {
			return rows, true
		}
		if !parser.take(',') {
			return nil, false
		}
		parser.skipSpace()
		if parser.peek(']') {
			// The observed connector does not emit trailing commas. Reject them
			// instead of silently broadening the accepted Python subset.
			return nil, false
		}
	}
}

func (parser *toolValueLineageSQLPythonParser) parseRow() (map[string]any, bool) {
	parser.skipSpace()
	if !parser.take('{') {
		return nil, false
	}
	parser.skipSpace()
	if parser.peek('}') {
		return nil, false
	}
	row := make(map[string]any)
	seen := make(map[string]struct{})
	for {
		key, ok := parser.parseString()
		if !ok || key == "" || strings.ContainsRune(key, 0) {
			return nil, false
		}
		folded := strings.ToLower(key)
		if _, duplicate := seen[folded]; duplicate {
			return nil, false
		}
		seen[folded] = struct{}{}
		parser.skipSpace()
		if !parser.take(':') {
			return nil, false
		}
		parser.skipSpace()
		value, ok := parser.parseScalar()
		if !ok {
			return nil, false
		}
		row[key] = value
		parser.elements++
		if parser.elements > toolValueLineageMaxJSONElements {
			return nil, false
		}
		parser.skipSpace()
		if parser.take('}') {
			return row, true
		}
		if !parser.take(',') {
			return nil, false
		}
		parser.skipSpace()
		if parser.peek('}') {
			return nil, false
		}
	}
}

func (parser *toolValueLineageSQLPythonParser) parseScalar() (any, bool) {
	if parser.peek('\'') {
		return parser.parseString()
	}
	if parser.takeKeyword("None") {
		return nil, true
	}
	start := parser.position
	if parser.peek('-') {
		parser.position++
	}
	digits := 0
	for parser.position < len(parser.raw) &&
		parser.raw[parser.position] >= '0' && parser.raw[parser.position] <= '9' {
		parser.position++
		digits++
	}
	if digits == 0 {
		parser.position = start
		return nil, false
	}
	if parser.peek('.') {
		parser.position++
		fraction := 0
		for parser.position < len(parser.raw) &&
			parser.raw[parser.position] >= '0' && parser.raw[parser.position] <= '9' {
			parser.position++
			fraction++
		}
		if fraction == 0 {
			parser.position = start
			return nil, false
		}
	}
	return json.Number(string(parser.raw[start:parser.position])), true
}

func (parser *toolValueLineageSQLPythonParser) parseString() (string, bool) {
	if !parser.take('\'') {
		return "", false
	}
	start := parser.position
	for parser.position < len(parser.raw) {
		character := parser.raw[parser.position]
		if character == '\\' || character == 0 || character == '\n' || character == '\r' {
			return "", false
		}
		if character == '\'' {
			value := string(parser.raw[start:parser.position])
			parser.position++
			if !utf8.ValidString(value) || len(value) > toolValueLineageMaxTokenBytes {
				return "", false
			}
			return value, true
		}
		parser.position++
	}
	return "", false
}

func (parser *toolValueLineageSQLPythonParser) skipSpace() {
	for parser.position < len(parser.raw) {
		switch parser.raw[parser.position] {
		case ' ', '\t', '\n', '\r':
			parser.position++
		default:
			return
		}
	}
}

func (parser *toolValueLineageSQLPythonParser) take(character byte) bool {
	if parser.position >= len(parser.raw) || parser.raw[parser.position] != character {
		return false
	}
	parser.position++
	return true
}

func (parser *toolValueLineageSQLPythonParser) peek(character byte) bool {
	return parser.position < len(parser.raw) && parser.raw[parser.position] == character
}

func (parser *toolValueLineageSQLPythonParser) takeKeyword(keyword string) bool {
	if !bytes.HasPrefix(parser.raw[parser.position:], []byte(keyword)) {
		return false
	}
	end := parser.position + len(keyword)
	if end < len(parser.raw) &&
		((parser.raw[end] >= 'A' && parser.raw[end] <= 'Z') ||
			(parser.raw[end] >= 'a' && parser.raw[end] <= 'z') ||
			(parser.raw[end] >= '0' && parser.raw[end] <= '9') || parser.raw[end] == '_') {
		return false
	}
	parser.position = end
	return true
}

func toolValueLineageSQLSensitiveValues(
	table actionfacts.SensitiveSQLTableClass,
	rows []map[string]any,
) ([]string, []string, bool) {
	var allowed map[string]struct{}
	ssnTable := false
	switch table {
	case actionfacts.SensitiveSQLTableCredentials:
		allowed = map[string]struct{}{"password": {}}
	case actionfacts.SensitiveSQLTableOAuthTokens:
		allowed = map[string]struct{}{"access_token": {}, "refresh_token": {}}
	case actionfacts.SensitiveSQLTableEmployees:
		allowed = map[string]struct{}{"ssn": {}}
		ssnTable = true
	default:
		return nil, nil, false
	}

	var tokens, ssns []string
	for _, row := range rows {
		for name, value := range row {
			if _, eligible := allowed[name]; !eligible {
				continue
			}
			text, ok := value.(string)
			if !ok || len(text) > toolValueLineageMaxTokenBytes ||
				!utf8.ValidString(text) || strings.ContainsRune(text, 0) ||
				toolValueLineageSQLDynamic(text) {
				return nil, nil, false
			}
			if ssnTable {
				if !toolValueLineageSQLExactSSN(text) {
					return nil, nil, false
				}
				ssns = append(ssns, text)
			} else if text != "" {
				tokens = append(tokens, text)
			}
			if len(tokens)+len(ssns) > toolValueLineageMaxTokens {
				return nil, nil, false
			}
		}
	}
	if len(tokens)+len(ssns) == 0 {
		return nil, nil, false
	}
	return tokens, ssns, true
}

func toolValueLineageSQLSinkLiteralTokens(value string) ([]string, []string, bool) {
	if value == "" || len(value) > toolValueLineageMaxInputBytes ||
		!utf8.ValidString(value) || strings.ContainsRune(value, 0) ||
		toolValueLineageSQLDynamic(value) {
		return nil, nil, false
	}
	var tokens, ssns []string
	for position := 0; position < len(value); {
		for position < len(value) && !toolValueLineageSQLTokenByte(value[position]) {
			position++
		}
		start := position
		for position < len(value) && toolValueLineageSQLTokenByte(value[position]) {
			position++
		}
		if start == position {
			continue
		}
		candidate := value[start:position]
		if toolValueLineageSQLExactSSN(candidate) {
			ssns = append(ssns, candidate)
		} else if toolValueLineageSQLCredentialShaped(candidate) {
			tokens = append(tokens, candidate)
		}
		if len(tokens)+len(ssns) > toolValueLineageMaxTokens {
			return nil, nil, false
		}
	}
	if len(tokens)+len(ssns) == 0 {
		return nil, nil, false
	}
	return tokens, ssns, true
}

func toolValueLineageSQLTokenByte(character byte) bool {
	return character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("_-$!:/+@%#?~", rune(character))
}

func toolValueLineageSQLCredentialShaped(value string) bool {
	if len(value) < toolValueLineageMinTokenBytes ||
		len(value) > toolValueLineageMaxTokenBytes {
		return false
	}
	var lower, upper, digit, symbol bool
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case character >= '0' && character <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	return digit && (lower || upper) && (symbol || lower && upper)
}

func toolValueLineageSQLExactSSN(value string) bool {
	if len(value) != 11 || value[3] != '-' || value[6] != '-' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if index == 3 || index == 6 {
			continue
		}
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return value[:3] != "000" && value[4:6] != "00" && value[7:] != "0000"
}

func toolValueLineageSQLDynamic(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "<%") || strings.Contains(value, "%>") ||
		strings.ContainsRune(value, '`')
}

func toolValueLineageSQLDigestSets(
	key [toolValueLineageKeyBytes]byte,
	tokens []string,
	ssns []string,
) ([]toolValueLineageDigest, bool) {
	if len(tokens)+len(ssns) == 0 || len(tokens)+len(ssns) > toolValueLineageMaxTokens {
		return nil, false
	}
	var digests []toolValueLineageDigest
	if len(tokens) != 0 {
		projected, ok := toolValueLineageDigestTokens(key, tokens)
		if !ok {
			return nil, false
		}
		digests = append(digests, projected...)
	}
	if len(ssns) != 0 {
		projected, ok := toolValueLineageSQLSSNDigests(key, ssns)
		if !ok {
			return nil, false
		}
		digests = append(digests, projected...)
	}
	if len(digests) == 0 || len(digests) > toolValueLineageMaxTokens {
		return nil, false
	}
	sort.Slice(digests, func(left, right int) bool {
		return bytes.Compare(digests[left][:], digests[right][:]) < 0
	})
	return digests, true
}

func toolValueLineageSQLSSNDigests(
	key [toolValueLineageKeyBytes]byte,
	ssns []string,
) ([]toolValueLineageDigest, bool) {
	if toolValueLineageZeroKey(key) || len(ssns) == 0 ||
		len(ssns) > toolValueLineageMaxTokens {
		return nil, false
	}
	unique := make(map[string]struct{}, len(ssns))
	for _, ssn := range ssns {
		if !toolValueLineageSQLExactSSN(ssn) {
			return nil, false
		}
		unique[ssn] = struct{}{}
	}
	digests := make([]toolValueLineageDigest, 0, len(unique))
	for ssn := range unique {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(toolValueLineageSQLSSNDomain))
		_, _ = mac.Write([]byte{0})
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(ssn)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(ssn))
		var digest toolValueLineageDigest
		copy(digest[:], mac.Sum(nil))
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(left, right int) bool {
		return bytes.Compare(digests[left][:], digests[right][:]) < 0
	})
	return digests, len(digests) != 0
}
