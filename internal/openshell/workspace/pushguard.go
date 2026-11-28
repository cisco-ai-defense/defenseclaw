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

package workspace

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrPlaceholderCommit refuses a push of the sandbox's commits: they sit on
// the commit that replaced the credential lines of tracked files with
// placeholders (CopyRecord.SandboxHead), so the pushed branch would put
// DC_SECRET_<n> over those lines upstream (RV6-4).
var ErrPlaceholderCommit = errors.New("the agent's commits sit on a commit that replaced your credentials with placeholders " +
	"(DC_SECRET_<n>), so a branch pushed from the sandbox would put the placeholders over them upstream. " +
	"Bring the work back with pull --branch and push it from this computer")

// CheckPushFromSandbox is the check before pull --push-branch (or any
// other push of the sandbox's commits) sends them upstream:
// ErrPlaceholderCommit when the copy replaced the credentials of a tracked
// file, nil otherwise.
func CheckPushFromSandbox(rec *CopyRecord) error {
	if rec != nil && rec.SandboxHead != "" && rec.SandboxHead != rec.Head {
		return ErrPlaceholderCommit
	}
	return nil
}

// writePlaceholderPrePush installs the copy's pre-push hook: it refuses a
// push whose commits contain commit ph (the placeholder commit).
func writePlaceholderPrePush(stage, ph string) error {
	dir := filepath.Join(stage, ".git", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	script := `#!/bin/sh
# DefenseClaw: refuse a push that carries the commit replacing your
# credentials with placeholders (an accident guard; see pull --branch).
ph=` + ph + `
while read -r lref lsha rref rsha; do
	case "$lsha" in *[!0]*) ;; *) continue ;; esac
	if git merge-base --is-ancestor "$ph" "$lsha" 2>/dev/null; then
		echo "DefenseClaw: this push carries commit $ph, which replaced credentials with placeholders (DC_SECRET_<n>). Bring the work back with defenseclaw substrate pull --branch and push it from your computer." >&2
		exit 1
	fi
done
exit 0
`
	return os.WriteFile(filepath.Join(dir, "pre-push"), []byte(script), 0o755)
}
