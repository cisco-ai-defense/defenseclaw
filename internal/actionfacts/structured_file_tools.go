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

package actionfacts

import "encoding/json"

const maxStructuredReadBatchPaths = 64

func extractExactSearchFilesArgs(raw json.RawMessage) extractedInput {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return problem
	}
	if len(object) != 2 {
		return structuredFileToolSchemaFailure()
	}
	pathValue, pathOK := exactStructuredLiteralPath(object, "path")
	_, patternOK := exactStructuredString(object, "pattern")
	if !pathOK || !patternOK {
		return structuredFileToolSchemaFailure()
	}
	return extractedInput{
		paths:  []extractedScalar{{key: "path", value: pathValue}},
		status: StatusComplete,
	}
}

func extractExactGetFileInfoArgs(raw json.RawMessage) extractedInput {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return problem
	}
	if len(object) != 1 {
		return structuredFileToolSchemaFailure()
	}
	pathValue, ok := exactStructuredLiteralPath(object, "path")
	if !ok {
		return structuredFileToolSchemaFailure()
	}
	return extractedInput{
		paths:  []extractedScalar{{key: "path", value: pathValue}},
		status: StatusComplete,
	}
}

func extractExactFSReadBatchArgs(raw json.RawMessage) extractedInput {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return problem
	}
	if len(object) != 1 {
		return structuredFileToolSchemaFailure()
	}
	value, ok := object["paths"]
	if !ok {
		return structuredFileToolSchemaFailure()
	}
	paths, ok := value.([]any)
	if !ok || len(paths) == 0 {
		return structuredFileToolSchemaFailure()
	}
	if len(paths) > maxStructuredReadBatchPaths {
		return extractedInput{
			status: StatusLimitExceeded,
			issues: []IssueCode{IssueInputLimit},
		}
	}

	out := extractedInput{
		paths:  make([]extractedScalar, 0, len(paths)),
		status: StatusComplete,
	}
	for _, item := range paths {
		pathValue, ok := item.(string)
		if !ok || !validStructuredLiteralPath(pathValue) ||
			validateScalar(pathValue, maxScalarBytes) != "" {
			return structuredFileToolSchemaFailure()
		}
		out.paths = append(out.paths, extractedScalar{
			key:   "path",
			value: pathValue,
		})
	}
	return out
}

func exactStructuredString(object map[string]any, key string) (string, bool) {
	value, ok := object[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok || validateScalar(text, maxScalarBytes) != "" {
		return "", false
	}
	return text, true
}

func exactStructuredLiteralPath(object map[string]any, key string) (string, bool) {
	value, ok := exactStructuredString(object, key)
	if !ok || !validStructuredLiteralPath(value) {
		return "", false
	}
	return value, true
}

func validStructuredLiteralPath(value string) bool {
	return value != "" && !containsPathGlob(value)
}

func containsPathGlob(value string) bool {
	for _, character := range value {
		switch character {
		case '*', '?', '[':
			return true
		}
	}
	return false
}

func structuredFileToolSchemaFailure() extractedInput {
	return extractedInput{
		status: StatusPartial,
		issues: []IssueCode{IssueUnknownOperandGrammar},
	}
}
