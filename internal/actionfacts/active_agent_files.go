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

import (
	"path"
	"strings"
)

const maxActiveAgentFiles = 32

func normalizeActiveAgentFiles(values []string) ([]string, IssueCode) {
	if len(values) > maxActiveAgentFiles {
		return nil, IssueInputLimit
	}
	if len(values) == 0 {
		return nil, ""
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if issue := validateScalar(value, maxScalarBytes); issue != "" {
			return nil, issue
		}
		normalized, windows, ok := normalizeActiveAgentFile(value)
		if !ok {
			return nil, IssueInvalidSyntax
		}
		key := normalized
		if windows {
			key = strings.ToLower(key)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	return out, ""
}

func normalizeCaseInsensitiveActiveAgentFiles(
	values []string,
	activeFiles []string,
) ([]string, IssueCode) {
	normalized, issue := normalizeActiveAgentFiles(values)
	if issue != "" {
		return nil, issue
	}
	for _, value := range normalized {
		if !strings.HasPrefix(value, "/") || !containsExactPath(activeFiles, value) {
			return nil, IssueInvalidSyntax
		}
	}
	return normalized, ""
}

func containsExactPath(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func normalizeActiveAgentFile(value string) (normalized string, windows bool, ok bool) {
	if value == "" || strings.TrimSpace(value) != value ||
		hasUnresolvedPathSyntax(value) {
		return "", false, false
	}
	if strings.HasPrefix(value, "/") {
		cleaned := path.Clean(value)
		if cleaned == "/" || len(cleaned) > maxScalarBytes {
			return "", false, false
		}
		return cleaned, false, true
	}
	parsed := parseWindowsPath(value)
	if !parsed.absolute || parsed.unresolved || parsed.normalized == "" ||
		parsed.normalized == parsed.volume+"/" ||
		len(parsed.normalized) > maxScalarBytes {
		return "", false, false
	}
	return parsed.normalized, true, true
}
