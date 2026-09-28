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

package enterprisehooks

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// maxWindowsCursorApprovedForeignHooks bounds the protected allowlist that
// every managed Cursor hook invocation reads.
const maxWindowsCursorApprovedForeignHooks = 256

// canonicalWindowsCursorApprovedForeignHooks normalizes the administrator
// allowlist to sorted, de-duplicated lowercase sha256 hex digests.
func canonicalWindowsCursorApprovedForeignHooks(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		value := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(entry)), "sha256:")
		if !validCursorApprovedForeignHookDigest(value) {
			return nil, fmt.Errorf("enterprise hooks: Cursor approved foreign hook %q is not a sha256 hex digest", entry)
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) > maxWindowsCursorApprovedForeignHooks {
		return nil, fmt.Errorf(
			"enterprise hooks: Cursor approved foreign hook allowlist has %d entries, maximum %d",
			len(result),
			maxWindowsCursorApprovedForeignHooks,
		)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

// validateWindowsCursorApprovedForeignHooks requires the exact canonical form
// written by canonicalWindowsCursorApprovedForeignHooks.
func validateWindowsCursorApprovedForeignHooks(values []string) error {
	if len(values) == 0 {
		if values != nil {
			return errors.New("enterprise hooks: Cursor approved foreign hook allowlist must be omitted when empty")
		}
		return nil
	}
	canonical, err := canonicalWindowsCursorApprovedForeignHooks(values)
	if err != nil {
		return err
	}
	if len(canonical) != len(values) {
		return errors.New("enterprise hooks: Cursor approved foreign hook allowlist is not canonical")
	}
	for index := range values {
		if canonical[index] != values[index] {
			return errors.New("enterprise hooks: Cursor approved foreign hook allowlist is not canonical")
		}
	}
	return nil
}

func equalWindowsCursorApprovedForeignHooks(published, configured []string) (bool, error) {
	want, err := canonicalWindowsCursorApprovedForeignHooks(configured)
	if err != nil {
		return false, err
	}
	if len(want) != len(published) {
		return false, nil
	}
	for index := range want {
		if want[index] != published[index] {
			return false, nil
		}
	}
	return true, nil
}

func validCursorApprovedForeignHookDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
