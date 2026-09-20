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

package connector

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedEnterpriseWindowsHookBinary returns the hook launcher installed beside
// the running gateway on a machine pinned to managed enterprise. The enterprise
// tree is administrator-provisioned at an operator-chosen root, so the native
// packaged proof — a Known Folder per-user Programs root plus a user-scoped
// install-state.json — does not describe it. Administrator ownership with no
// untrusted writer on the launcher and every ancestor is the proof instead, the
// same one the enterprise guardian applies to its authoritative executable.
// An empty result leaves the caller on its existing resolution order.
func managedEnterpriseWindowsHookBinary(executable string) string {
	if !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return ""
	}
	executable, err := filepath.Abs(executable)
	if err != nil {
		return ""
	}
	hook := filepath.Clean(filepath.Join(filepath.Dir(executable), windowsHookBinaryName))
	if !stableNativeWindowsPE(hook) {
		return ""
	}
	if err := managed.ValidateTrustedFilePath(hook, "enterprise hook executable"); err != nil {
		return ""
	}
	return hook
}
