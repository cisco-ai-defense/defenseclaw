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

package gateway

import (
	"path/filepath"
	"runtime"
)

// clientWriteTarget returns the hook client's resolved target for a path
// spelling of a write operand. The client keys its map by the path as its own
// operating system spells it: on Windows the native path
// (C:\Users\u\.defenseclaw\config.yaml). The POSIX reading of the same call
// (a Git Bash Bash tool, or a PowerShell call the partial reading places
// with forward slashes) spells it C:/Users/u/.defenseclaw/config.yaml, so a
// managed gateway, which may not resolve the user home itself, found no
// target and proved no state write: a redirect into the state from a call
// the analysis read in part was allowed on Windows only
// (rel-1-0-10:GAP-0982). On Windows the native spelling of the same path is
// looked up too; elsewhere the spelling is the key.
func clientWriteTarget(targets map[string]string, spelling string) (string, bool) {
	if value, found := targets[spelling]; found {
		return value, true
	}
	if runtime.GOOS != "windows" || spelling == "" {
		return "", false
	}
	native := filepath.Clean(filepath.FromSlash(spelling))
	if native == spelling {
		return "", false
	}
	value, found := targets[native]
	return value, found
}
