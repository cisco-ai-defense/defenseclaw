// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const (
	literalSensitiveUploadClassCredential = "credential"
	maxLiteralSensitiveUploadBytes        = 64 * 1024
	maxLiteralSensitiveUploadDepth        = 6
	maxLiteralSensitiveUploadValues       = 512
)

var literalSensitiveUploadKeys = map[string]struct{}{
	"access_key": {}, "api_key": {}, "apikey": {}, "client_secret": {},
	"credential": {}, "credentials": {}, "db_pass": {}, "password": {},
	"private_key": {}, "secret": {}, "secret_key": {}, "token": {},
}

// ExactLiteralSensitiveUploads returns a defensive copy of value-free facts.
func ExactLiteralSensitiveUploads(facts Facts) []LiteralSensitiveUploadFact {
	result := make([]LiteralSensitiveUploadFact, 0, len(facts.LiteralSensitiveUploads))
	for _, fact := range facts.LiteralSensitiveUploads {
		if fact.CommandID > 0 && fact.Class == literalSensitiveUploadClassCredential {
			result = append(result, fact)
		}
	}
	return result
}

func projectLiteralSensitiveUploads(facts Facts) []LiteralSensitiveUploadFact {
	if !facts.Authoritative() {
		return nil
	}
	result := make([]LiteralSensitiveUploadFact, 0, 1)
	for _, command := range facts.Commands {
		if command.Effect != EffectExecute || command.ControlFlowUncertain ||
			(command.Program != "curl" && command.Program != "curl.exe") {
			continue
		}
		for _, payload := range StaticCurlUploadPayloads(command) {
			if literalJSONHasSensitiveCredential(payload) {
				result = append(result, LiteralSensitiveUploadFact{
					CommandID: command.ID,
					Class:     literalSensitiveUploadClassCredential,
				})
				break
			}
		}
	}
	return result
}

func literalJSONHasSensitiveCredential(payload string) bool {
	if payload == "" || len(payload) > maxLiteralSensitiveUploadBytes ||
		!json.Valid([]byte(payload)) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return false
	}
	count := 0
	return literalJSONValueHasSensitiveCredential(value, 0, &count)
}

func literalJSONValueHasSensitiveCredential(value any, depth int, count *int) bool {
	if depth > maxLiteralSensitiveUploadDepth || *count >= maxLiteralSensitiveUploadValues {
		return false
	}
	*count++
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
			if _, sensitive := literalSensitiveUploadKeys[normalized]; sensitive &&
				literalSensitiveCredentialValue(child) {
				return true
			}
			if literalJSONValueHasSensitiveCredential(child, depth+1, count) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if literalJSONValueHasSensitiveCredential(child, depth+1, count) {
				return true
			}
		}
	}
	return false
}

func literalSensitiveCredentialValue(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	return len(text) >= 8 && len(text) <= 4096 &&
		!strings.HasPrefix(text, "$") && !strings.HasPrefix(text, "$"+"{")
}
