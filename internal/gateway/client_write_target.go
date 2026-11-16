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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// clientWriteTargets returns the hook client's resolved targets for one write
// operand, given the operand as written and its spellings (resolved, as
// written, normalized), in the order to try them.
//
// Every exact key comes first, in spelling order, as on every system: the
// client keys its map by the operand as it was written.
//
// On Windows the native spelling of the same operand is looked up after
// that. The POSIX reading of a call (a Git Bash Bash tool, or a PowerShell
// call the partial reading places with forward slashes) spells
// C:/Users/u/.defenseclaw/config.yaml where the client keyed
// C:\Users\u\.defenseclaw\config.yaml, so a managed gateway, which may not
// resolve the user home itself, found no target and proved no state write
// (rel-1-0-10:GAP-0982). Only the separators change, and only of a spelling
// the filesystem walk resolves. When the operand as written has a ..
// component, a spelling the analysis cleaned lexically names another file:
// across a junction jx\..\.defenseclaw is the state, while the cleaned
// .\.defenseclaw is an ordinary folder the same call may write first, whose
// entry would then answer for the state write (rel-1-0-10:GAP-1006). Such an
// operand is respelled only as written.
func clientWriteTargets(targets map[string]string, written string, spellings ...string) []string {
	var found []string
	for _, spelling := range spellings {
		if value, ok := targets[spelling]; ok {
			found = append(found, value)
		}
	}
	if runtime.GOOS != "windows" {
		return found
	}
	if hasDotDotSegment(written) {
		spellings = []string{written}
	}
	for _, spelling := range spellings {
		native := filepath.FromSlash(spelling)
		if spelling == "" || native == spelling {
			continue
		}
		if _, resolved := hookpaths.ResolveWriteTarget(native); !resolved {
			continue
		}
		if value, ok := targets[native]; ok {
			found = append(found, value)
		}
	}
	return found
}

// hasDotDotSegment reports a .. component under either separator.
func hasDotDotSegment(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}
