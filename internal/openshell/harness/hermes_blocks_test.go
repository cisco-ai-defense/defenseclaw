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

import (
	"encoding/base64"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hermesStandIn is the part of Hermes 0.19.0 the block-notice shim works
// with: hermes_cli.plugins.resolve_pre_tool_block, which returns the block
// message of a blocked tool call (DefenseClaw's reason) or None, and the
// CLI's printer, cli._cprint.
var hermesStandIn = map[string]string{
	"hermes_cli/__init__.py": "",
	"hermes_cli/plugins.py": `"""Stand-in plugins module."""
CALLS = []


def resolve_pre_tool_block(tool_name, args, task_id="", session_id=""):
    """Resolve the pre_tool_call directive."""
    CALLS.append((tool_name, args, task_id))
    if tool_name == "terminal":
        return "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach."
    if tool_name == "write_file":
        return "DefenseClaw blocked this tool call because its policy check failed: sandbox ingress unreachable"
    return None
`,
	"cli.py": `PRINTED = []


def _cprint(text):
    PRINTED.append(text)
`,
}

// TestHermesBlockNoticeShim runs the shim the Hermes image imports at every
// start against a stand-in Hermes: a blocked tool call's message is printed
// with the CLI's printer, in Hermes' tool-line style, when stdout is a
// terminal, and never otherwise; what the call returns (the tool error the
// model gets) is unchanged, and the patched module keeps its own loader.
func TestHermesBlockNoticeShim(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	for name, body := range hermesStandIn {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(body))
	}
	writeFile(t, filepath.Join(dir, hermesBlockNoticeModuleName+".py"), []byte(hermesBlockNoticeModule))
	script := `import os, sys
sys.path.insert(0, sys.argv[1])
import ` + hermesBlockNoticeModuleName + `
os.isatty = lambda fd: sys.argv[2] == "tty"
import cli
from hermes_cli import plugins
from hermes_cli.plugins import resolve_pre_tool_block
assert type(plugins.__loader__).__name__ == "SourceFileLoader", plugins.__loader__
assert resolve_pre_tool_block.__doc__ == "Resolve the pre_tool_call directive."
assert resolve_pre_tool_block("terminal", {"command": "x"}, task_id="t1").startswith("Blocked by DefenseClaw rule E2E-SANDBOX-MARKER")
assert resolve_pre_tool_block("read_file", {"path": "a"}) is None
assert resolve_pre_tool_block(tool_name="write_file", args={}).startswith("DefenseClaw blocked this tool call")
assert plugins.CALLS == [("terminal", {"command": "x"}, "t1"), ("read_file", {"path": "a"}, ""), ("write_file", {}, "")], plugins.CALLS
for line in cli.PRINTED:
    print(line)
`
	for _, tc := range []struct {
		stdout string
		want   []string
	}{
		{"tty", []string{
			"  ┊ ✗ terminal blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach.",
			"  ┊ ✗ write_file blocked: DefenseClaw blocked this tool call because its policy check failed: sandbox ingress unreachable",
		}},
		{"pipe", nil},
	} {
		t.Run(tc.stdout, func(t *testing.T) {
			out, err := exec.Command(python, "-I", "-c", script, dir, tc.stdout).CombinedOutput()
			if err != nil {
				t.Fatalf("shim run: %v\n%s", err, out)
			}
			var got []string
			if s := strings.TrimRight(string(out), "\n"); s != "" {
				got = strings.Split(s, "\n")
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("printed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
	// A long message is cut to one line of 300 characters.
	long := `import os, sys
sys.path.insert(0, sys.argv[1])
import ` + hermesBlockNoticeModuleName + ` as shim
os.isatty = lambda fd: True
import cli
shim._defenseclaw_block_notice("terminal", "Blocked by DefenseClaw rule R: " + "x\n" * 400)
print(len(cli.PRINTED[0]), cli.PRINTED[0].endswith("..."), "\n" in cli.PRINTED[0])
`
	out, err := exec.Command(python, "-I", "-c", long, dir).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "306 True False" {
		t.Fatalf("long notice: %v %q", err, out)
	}
	// The install writes the shim and its .pth into the tool environment.
	steps, err := Hermes.InstallSteps("")
	if err != nil || len(steps) != 1 {
		t.Fatalf("install steps = %v, %v", steps, err)
	}
	for _, want := range []string{
		base64.StdEncoding.EncodeToString([]byte(hermesBlockNoticeModule)),
		`>"$site/` + hermesBlockNoticeModuleName + `.py"`, `printf 'import ` + hermesBlockNoticeModuleName + `\n' >"$site/` + hermesBlockNoticeModuleName + `.pth"`,
	} {
		if !strings.Contains(steps[0].Run, want) {
			t.Fatalf("the Hermes install does not write %q:\n%s", want, steps[0].Run)
		}
	}
	shParses(t, "Hermes install step", steps[0].Run)
}

// TestHermesInstallStampsTheImageInstallMethod: the image writes Hermes'
// code-scoped install-method stamp, root-owned, next to the code Hermes
// resolves it from (the site-packages the hermes_cli package lives in), so
// Hermes reads the install as an image instead of an unsupported pip install
// (no notice, no pypi.org update check at start).
func TestHermesInstallStampsTheImageInstallMethod(t *testing.T) {
	steps, err := Hermes.InstallSteps("")
	if err != nil || len(steps) != 1 {
		t.Fatalf("install steps = %v, %v", steps, err)
	}
	run := steps[0].Run
	stamp := `printf 'docker\n' >"$site/.install_method"; chown root:root "$site/.install_method"; chmod 0644 "$site/.install_method"`
	if hermesInstallMethod != "docker" || !strings.Contains(run, stamp) {
		t.Fatalf("the Hermes install does not stamp the install method:\n%s", run)
	}
	// $site is the checked site-packages of the pinned tool environment.
	if site := strings.LastIndex(run, `site="$(`); site < 0 || site > strings.Index(run, stamp) ||
		!strings.Contains(run[site:], `case "$site" in `+InstallRootBase+`/hermes/*)`) {
		t.Fatalf("the stamp is not written into the checked site-packages:\n%s", run)
	}
}
