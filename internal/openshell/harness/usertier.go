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

package harness

import "strings"

// restoreUserHooksScript is the launcher fragment that puts a user-tier hook
// file back from its root-owned canonical copy before every start (OpenHands
// and agy read their hooks only from a file in the workload-writable HOME).
// dir and file are paths the shell expands inside double quotes (they may
// name $home); links are the paths, dir and file among them, that must not
// be symbolic links; displayName names the harness in the refusals.
//
// The file must be a regular file afterwards, byte for byte the canonical
// copy. A target that exists as anything else is refused up front: `mv -f`
// onto a directory moves the new file inside it and exits 0, so the harness
// would start with the directory where its hooks file should be, and no
// DefenseClaw hook. The check after the rename catches the same state
// appearing in between, and any restore that did not land.
func restoreUserHooksScript(displayName, canonical, dir, file string, links ...string) string {
	q := func(p string) string { return `"` + p + `"` }
	noHooks := "refusing to start " + displayName + " without DefenseClaw's hooks"
	var b strings.Builder
	b.WriteString("canonical=" + q(canonical) + "\n")
	b.WriteString("if")
	for i, l := range links {
		if i > 0 {
			b.WriteString(" ||")
		}
		b.WriteString(" [ -L " + q(l) + " ]")
	}
	b.WriteString("; then\n" +
		"  echo \"defenseclaw: " + dir + " is reached through a symbolic link; refusing to start " + displayName + "\" >&2\n" +
		"  exit 2\nfi\n")
	b.WriteString("if [ -e " + q(file) + " ] && [ ! -f " + q(file) + " ]; then\n" +
		"  echo \"defenseclaw: " + file + " is not a regular file; " + noHooks + " (remove it and start " + displayName + " again)\" >&2\n" +
		"  exit 2\nfi\n")
	b.WriteString("if ! /bin/mkdir -p " + q(dir) + " 2>/dev/null; then\n" +
		"  echo \"defenseclaw: cannot create " + dir + "; " + noHooks + "\" >&2\n" +
		"  exit 2\nfi\n")
	b.WriteString("tmp=\"$(/usr/bin/mktemp " + q(file+".XXXXXX") + " 2>/dev/null)\" || tmp=\"\"\n")
	b.WriteString("if [ -z \"$tmp\" ] || ! /bin/cat \"$canonical\" >\"$tmp\" 2>/dev/null || ! /bin/mv -f \"$tmp\" " + q(file) + " 2>/dev/null ||\n" +
		"  [ -L " + q(file) + " ] || [ ! -f " + q(file) + " ] || ! /usr/bin/cmp -s \"$canonical\" " + q(file) + "; then\n" +
		"  [ -z \"$tmp\" ] || /bin/rm -f \"$tmp\" 2>/dev/null\n" +
		"  echo \"defenseclaw: cannot restore " + file + "; " + noHooks + "\" >&2\n" +
		"  exit 2\nfi\n")
	b.WriteString("unset canonical tmp\n")
	return b.String()
}
