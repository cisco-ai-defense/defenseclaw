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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
)

// BundledSkillContainer is the reserved directory name Codex uses for its
// first-party system-skill cache. The name alone is not trusted: only entries
// at or below `$CODEX_HOME/skills/.system` are bundled. A same-named directory
// under an operator or workspace skill root remains scan/enforcement eligible.
const BundledSkillContainer = ".system"

// ErrBundledSkill is the sentinel returned by every mutation path
// that refuses to act on a bundled-skill container or descendant.
// Callers surface it verbatim (HTTP 409 with code
// "bundled_skill_refused" at the REST boundary; a distinct exit code
// at the CLI). The mutation must be a no-op — no partial move, no
// audit-store side effects — because a corrupted bundled skill is a
// vendor-supplied component and cannot be restored by the operator.
var ErrBundledSkill = errors.New(
	"enforce: bundled skill is vendor-managed and cannot be blocked, disabled, or quarantined",
)

// IsBundledSkillPath reports whether path is at or below Codex's exact
// vendor-managed system-skill cache, or inside an unchanged Hermes skill whose
// identity/content match both HERMES_HOME/skills/.bundled_manifest and the
// corresponding source in the exact Hermes checkout.
// Modified/untracked Hermes skills and a directory merely named ".system"
// elsewhere remain operator-controlled and must not bypass scanning or
// enforcement.
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
	if isCodexBundledSkillPath(trimmed) {
		return true
	}
	return hermesskills.IsBundledPath(trimmed)
}

func isCodexBundledSkillPath(path string) bool {
	codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codexHome == "" {
		userHome, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(userHome) == "" {
			return false
		}
		codexHome = filepath.Join(userHome, ".codex")
	} else if codexHome == "~" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		codexHome = userHome
	} else if strings.HasPrefix(codexHome, "~/") || strings.HasPrefix(codexHome, `~\`) {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		codexHome = filepath.Join(userHome, codexHome[2:])
	}
	if !filepath.IsAbs(codexHome) {
		absolute, err := filepath.Abs(codexHome)
		if err != nil {
			return false
		}
		codexHome = absolute
	}
	return pathAtOrBelow(path, filepath.Join(codexHome, "skills", BundledSkillContainer))
}

func pathAtOrBelow(path, root string) bool {
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		pathAbs = strings.ToLower(pathAbs)
		rootAbs = strings.ToLower(rootAbs)
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// IsBundledSkillContainerName reports whether the given basename is
// exactly the reserved BundledSkillContainer name. Used by the
// discovery walker to decide when to recurse one level into a
// `.system` directory instead of emitting it as an ordinary skill
// entry. Prefer IsBundledSkillPath for any check on a full path.
func IsBundledSkillContainerName(basename string) bool {
	return strings.TrimSpace(basename) == BundledSkillContainer
}
