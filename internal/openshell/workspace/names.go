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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// ProjectLabelKey is the OpenShell sandbox label that ties a sandbox to
	// the host folder it works on. Its value is ProjectKey(realpath).
	ProjectLabelKey = "io.defenseclaw/project"
	// ModeLabelKey records whether the sandbox mounts the folder or works on
	// a copy ("mount" or "copy").
	ModeLabelKey = "io.defenseclaw/workdir-mode"

	// DefaultTargetRoot is the container directory project and context
	// mounts live under.
	DefaultTargetRoot = "/work"
)

// nameRE accepts sandbox names that are also safe as a single git ref
// component and as a file name: no leading dot or dash, no "..", no
// ".lock" suffix, no path separators.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidateName checks a sandbox name before it is used in refs and paths.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") ||
		strings.HasSuffix(name, ".lock") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("workspace: invalid sandbox name %q (use letters, digits, '.', '_' and '-', at most 63 characters)", name)
	}
	return nil
}

// ProjectKey is the stable identity of a host folder: the first 128 bits of
// sha256 over its cleaned real path, hex encoded. It stays under the 63
// character label-value limit OpenShell inherits from Kubernetes.
func ProjectKey(realPath string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(realPath)))
	return hex.EncodeToString(sum[:16])
}

// ProjectLabel returns the label pair to attach to a sandbox created for
// realPath. Resume detection looks sandboxes up by it.
func ProjectLabel(realPath string) (key, value string) {
	return ProjectLabelKey, ProjectKey(realPath)
}

var repoNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// RepoName derives the /work/<repo> directory name from a host folder.
func RepoName(realPath string) string {
	base := filepath.Base(filepath.Clean(realPath))
	base = repoNameUnsafe.ReplaceAllString(base, "-")
	base = strings.Trim(base, ".-")
	if base == "" {
		return "project"
	}
	if len(base) > 64 {
		base = base[:64]
	}
	return base
}
