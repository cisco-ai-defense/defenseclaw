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

//go:build windows

package connector

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ensureClaudeCodeConfigDir protects a directory DefenseClaw creates, but does
// not rewrite the ACL of an operator's existing Claude configuration tree.
// Existing trees are instead validated with the same owner, DACL, ancestor,
// and reparse-point contract used for scoped token storage and fail closed when
// another principal could replace settings.json.
func ensureClaudeCodeConfigDir(path string) error {
	created, err := safefile.CreatePrivateDirectory(path)
	if err != nil {
		return fmt.Errorf("create private Claude Code configuration directory: %w", err)
	}
	if err := hookAPIValidateDirectory(path); err != nil {
		state := "existing"
		if created {
			state = "new"
		}
		return fmt.Errorf("validate %s Claude Code configuration directory: %w", state, err)
	}
	return nil
}
