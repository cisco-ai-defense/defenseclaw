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

// openHandsStandIn is the part of the OpenHands SDK the session-end shim
// works with (openhands is a namespace package there too): a
// HookEventProcessor whose run_session_end runs the hooks and then hands
// each result to the UI callback, which raises once the Textual app has
// stopped, as OpenHands 1.16.0's does at interpreter exit.
var openHandsStandIn = map[string]string{
	"openhands/sdk/__init__.py":       "",
	"openhands/sdk/hooks/__init__.py": "",
	"openhands/sdk/hooks/conversation_hooks.py": `RAN = []


class HookEventProcessor:
    def __init__(self, original_callback):
        self.original_callback = original_callback

    def _emit_hook_execution_event(self, hook_event_type, hook_command, result):
        self.original_callback((hook_event_type, hook_command, result))

    def run_session_end(self):
        """Run SessionEnd hooks. Call before conversation is closed."""
        RAN.append("SessionEnd")
        self._emit_hook_execution_event(hook_event_type="SessionEnd", hook_command="/hook.sh", result="ok")

    def run_stop(self):
        RAN.append("Stop")
        self._emit_hook_execution_event(hook_event_type="Stop", hook_command="/hook.sh", result="ok")
`,
}

// TestOpenHandsSessionEndShim runs the shim the OpenHands image imports at
// every start against the stand-in: SessionEnd hooks still run and a UI
// that stopped no longer raises out of run_session_end (the atexit
// traceback), a UI that is still running still gets the event, and every
// other hook's events, and their errors, are unchanged.
func TestOpenHandsSessionEndShim(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	for name, body := range openHandsStandIn {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(body))
	}
	writeFile(t, filepath.Join(dir, openHandsShimModuleName+".py"), []byte(openHandsShimModule))
	script := `import sys
sys.path.insert(0, sys.argv[1])
import ` + openHandsShimModuleName + `
from openhands.sdk.hooks import conversation_hooks as hooks
assert type(hooks.__loader__).__name__ == "SourceFileLoader", hooks.__loader__
assert hooks.HookEventProcessor.run_session_end.__doc__.startswith("Run SessionEnd hooks")

def stopped(event):
    raise RuntimeError("App is not running")

seen = []
p = hooks.HookEventProcessor(stopped)
p.run_session_end()
assert hooks.RAN == ["SessionEnd"], hooks.RAN
assert "_emit_hook_execution_event" not in vars(p)
try:
    p.run_stop()
except RuntimeError:
    print("other events unchanged")
hooks.HookEventProcessor(seen.append).run_session_end()
assert seen == [("SessionEnd", "/hook.sh", "ok")], seen
print("session end ok")
`
	out, err := exec.Command(python, "-I", "-c", script, dir).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "other events unchanged\nsession end ok" {
		t.Fatalf("shim run: %v\n%s", err, out)
	}
	// The install writes the shim and its .pth into the tool environment.
	steps, err := OpenHands.InstallSteps("")
	if err != nil || len(steps) != 1 {
		t.Fatalf("install steps = %v, %v", steps, err)
	}
	run := steps[0].Run
	for _, want := range []string{
		base64.StdEncoding.EncodeToString([]byte(openHandsShimModule)),
		`case "$site" in ` + InstallRootBase + `/openhands/*)`,
		`printf 'import ` + openHandsShimModuleName + `\n' >"$site/` + openHandsShimModuleName + `.pth"`,
	} {
		if !strings.Contains(run, want) {
			t.Fatalf("the OpenHands install does not write %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, "\n") {
		t.Fatal("the OpenHands install step spans lines (a Dockerfile RUN is one line)")
	}
	shParses(t, "OpenHands install step", run)
}

// TestOpenHandsShimQuietsAuthlib: Authlib's deprecation warning, which
// Authlib always shows and the OpenHands SDK triggers at every start, is
// ignored; every other warning still shows.
func TestOpenHandsShimQuietsAuthlib(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"authlib/__init__.py": "",
		"authlib/deprecate.py": `import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter("always", AuthlibDeprecationWarning)


def deprecate(message):
    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=2)
`,
		"authlib/jose/__init__.py": `from authlib.deprecate import deprecate

deprecate("authlib.jose module is deprecated, please use joserfc instead.")
`,
	} {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(body))
	}
	writeFile(t, filepath.Join(dir, openHandsShimModuleName+".py"), []byte(openHandsShimModule))
	script := `import sys, warnings
sys.path.insert(0, sys.argv[1])
if sys.argv[2] == "shim":
    import ` + openHandsShimModuleName + `
import authlib.jose
warnings.warn("another warning", UserWarning)
`
	for _, tc := range []struct {
		mode      string
		wantJose  bool
		wantOther bool
	}{{"shim", false, true}, {"none", true, true}} {
		out, err := exec.Command(python, "-I", "-c", script, dir, tc.mode).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.mode, err, out)
		}
		if got := strings.Contains(string(out), "authlib.jose module is deprecated"); got != tc.wantJose {
			t.Errorf("%s: Authlib warning shown = %v, want %v:\n%s", tc.mode, got, tc.wantJose, out)
		}
		if got := strings.Contains(string(out), "another warning"); got != tc.wantOther {
			t.Errorf("%s: other warning shown = %v, want %v:\n%s", tc.mode, got, tc.wantOther, out)
		}
	}
}

// openHandsEventStandIn is the part of OpenHands the block-title patch works
// with: rich's Text and the SDK's frozen HookExecutionEvent, whose
// rendering starts "Hook: <event> (<tool>)" and puts the reason after
// "Status: BLOCKED - ".
var openHandsEventStandIn = map[string]string{
	"rich/__init__.py": "",
	"rich/text.py": `class Text:
    def __init__(self):
        self.parts = []

    def append(self, text, style=None):
        self.parts.append(text)

    def append_text(self, other):
        self.parts.extend(other.parts)

    def __str__(self):
        return "".join(self.parts)
`,
	"openhands/sdk/__init__.py":       "",
	"openhands/sdk/event/__init__.py": "",
	"openhands/sdk/event/hook_execution.py": `from rich.text import Text


class HookExecutionEvent:
    def __init__(self, blocked, reason):
        self.blocked, self.reason = blocked, reason

    def model_copy(self, update):
        copy = HookExecutionEvent(self.blocked, self.reason)
        copy.__dict__.update(update)
        return copy

    @property
    def visualize(self):
        """Rich rendering."""
        text = Text()
        text.append("Hook: PreToolUse (terminal)\n")
        text.append("Status: BLOCKED" if self.blocked else "Status: SUCCESS")
        if self.blocked and self.reason:
            text.append(" - " + self.reason)
        text.append("\nExit Code: 2")
        return text
`,
}

// TestOpenHandsShimLeadsWithADefenseClawBlock: a hook line blocked with
// DefenseClaw's reason renders the block first, where the TUI's collapsed
// title (the rendering's first 70 characters) shows the rule; other blocks
// and allowed calls render as OpenHands renders them.
func TestOpenHandsShimLeadsWithADefenseClawBlock(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	for name, body := range openHandsEventStandIn {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(body))
	}
	writeFile(t, filepath.Join(dir, openHandsShimModuleName+".py"), []byte(openHandsShimModule))
	script := `import sys
sys.path.insert(0, sys.argv[1])
import ` + openHandsShimModuleName + `
from openhands.sdk.event.hook_execution import HookExecutionEvent as E
assert E.visualize.__doc__ == "Rich rendering."
for event in (
    E(True, "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach."),
    E(True, "DefenseClaw hook failed closed"),
    E(True, "Blocked by hook"),
    E(False, None),
):
    print(str(event.visualize).replace("\n", " | "))
`
	out, err := exec.Command(python, "-I", "-c", script, dir).CombinedOutput()
	want := "BLOCKED by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach. | Hook: PreToolUse (terminal) | Status: BLOCKED | Exit Code: 2\n" +
		"BLOCKED: DefenseClaw hook failed closed | Hook: PreToolUse (terminal) | Status: BLOCKED | Exit Code: 2\n" +
		"Hook: PreToolUse (terminal) | Status: BLOCKED - Blocked by hook | Exit Code: 2\n" +
		"Hook: PreToolUse (terminal) | Status: SUCCESS | Exit Code: 2\n"
	if err != nil || string(out) != want {
		t.Fatalf("shim run: %v\n%s\nwant:\n%s", err, out, want)
	}
}
