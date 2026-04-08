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

package capability

import (
	"fmt"
	"path/filepath"
)

// MatchConstraints checks whether params satisfy all constraints.
// Returns true if every constraint key in the map is satisfied by the
// corresponding param value.
func MatchConstraints(constraints, params map[string]any) bool {
	if len(constraints) == 0 {
		return true
	}
	if params == nil {
		return false
	}

	for key, constraint := range constraints {
		paramVal, ok := params[key]
		if !ok {
			return false
		}
		if !matchValue(constraint, paramVal) {
			return false
		}
	}
	return true
}

func matchValue(constraint, param any) bool {
	switch cv := constraint.(type) {
	case string:
		return matchString(cv, param)
	case []any:
		return matchList(cv, param)
	default:
		// Fallback: exact equality via string representation
		return fmt.Sprint(constraint) == fmt.Sprint(param)
	}
}

// matchString matches a string constraint against a param value.
// Uses filepath.Match for glob patterns.
func matchString(pattern string, param any) bool {
	paramStr, ok := param.(string)
	if !ok {
		paramStr = fmt.Sprint(param)
	}

	// Try glob match first
	matched, err := filepath.Match(pattern, paramStr)
	if err != nil {
		// Invalid pattern — fall back to exact match
		return pattern == paramStr
	}
	return matched
}

// matchList checks that every element in the param list is present in the
// constraint's allowed list.
func matchList(allowed []any, param any) bool {
	paramList, ok := toStringSlice(param)
	if !ok {
		// Single value — check if it's in the allowed list
		paramStr := fmt.Sprint(param)
		for _, a := range allowed {
			if fmt.Sprint(a) == paramStr {
				return true
			}
		}
		return false
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[fmt.Sprint(a)] = true
	}

	for _, p := range paramList {
		if !allowedSet[p] {
			return false
		}
	}
	return true
}

func toStringSlice(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []any:
		result := make([]string, len(vv))
		for i, item := range vv {
			result[i] = fmt.Sprint(item)
		}
		return result, true
	case []string:
		return vv, true
	default:
		return nil, false
	}
}
