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
	writeFile(t, filepath.Join(dir, openHandsSessionEndModuleName+".py"), []byte(openHandsSessionEndModule))
	script := `import sys
sys.path.insert(0, sys.argv[1])
import ` + openHandsSessionEndModuleName + `
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
		base64.StdEncoding.EncodeToString([]byte(openHandsSessionEndModule)),
		`case "$site" in ` + InstallRootBase + `/openhands/*)`,
		`printf 'import ` + openHandsSessionEndModuleName + `\n' >"$site/` + openHandsSessionEndModuleName + `.pth"`,
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
