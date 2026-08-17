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

package enforce

import (
	"errors"
	"path/filepath"
	"strings"
)

// BundledSkillContainer is the reserved directory name that Codex and
// compatible agents use to ship first-party ("system") skills that are
// managed by the vendor and must not be blocked, disabled, quarantined,
// or otherwise mutated by DefenseClaw. Any skill entry that lives at or
// below `<skills-root>/.system/…` is treated as bundled.
const BundledSkillContainer = ".system"

// ErrBundledSkill is the sentinel returned by every mutation path
// that refuses to act on a bundled-skill container or descendant.
// Callers surface it verbatim (HTTP 409 with code
// "bundled_skill_refused" at the REST boundary; a distinct exit code
// at the CLI). The mutation must be a no-op — no partial move, no
// audit-store side effects — because a corrupted bundled skill is a
// vendor-supplied component and cannot be restored by the operator.
var ErrBundledSkill = errors.New(
	"enforce: bundled skill (.system container or descendant) is vendor-managed and cannot be blocked, disabled, or quarantined",
)

// IsBundledSkillPath reports whether path is at or below a
// BundledSkillContainer segment. The check is component-wise on the
// cleaned path so a directory literally named ".system" as an
// intermediate segment triggers, but a file whose basename happens to
// contain the substring ".system" (e.g. `hello.system.md`) does not.
//
// Path is Cleaned before check. Symlink resolution is the caller's
// responsibility: mutation surfaces MUST resolve symlinks (via
// filepath.EvalSymlinks or O_NOFOLLOW open + Fstat) before calling
// this — otherwise an attacker who can write a symlink outside the
// bundled tree pointing INTO `.system/hello` could bypass the guard.
//
// An empty path returns false. That's the correct behavior for the
// path-less mutation surfaces (PolicyEngine.Block/Quarantine/Disable
// callers that haven't associated a source_path yet); the missing
// source path is caught by the missing-provenance rule at the layer
// above, not silently treated as "bundled".
func IsBundledSkillPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}
	cleaned := filepath.Clean(trimmed)
	// filepath.Clean strips a trailing separator, so components split
	// on the OS-specific separator here matches what a caller sees
	// when it navigates the tree via ReadDir.
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == BundledSkillContainer {
			return true
		}
	}
	return false
}

// IsBundledSkillContainerName reports whether the given basename is
// exactly the reserved BundledSkillContainer name. Used by the
// discovery walker to decide when to recurse one level into a
// `.system` directory instead of emitting it as an ordinary skill
// entry. Prefer IsBundledSkillPath for any check on a full path.
func IsBundledSkillContainerName(basename string) bool {
	return strings.TrimSpace(basename) == BundledSkillContainer
}
