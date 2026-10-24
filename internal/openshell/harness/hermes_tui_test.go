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
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1036 / GAP-1078: the pinned Hermes builds the agent of its TUI,
// dashboard chat and serve backend without the shell hooks. The image keeps
// the refusals only while its pin is such a release: the host refuses the
// same releases, and a pin past them must drop the shim and the refusals.
func TestHermesImageRefusesTheUnhookedTUIOfItsPin(t *testing.T) {
	if got := connector.ResolveHookContract("hermes", Hermes.DefaultVersion); !got.KnownBroken {
		t.Fatalf("the image pins Hermes %s, whose TUI runs the hooks (%+v): remove hermesUnhookedAgentModule and the launcher's TUI refusals",
			Hermes.DefaultVersion, got)
	}
	steps, err := Hermes.InstallSteps("")
	if err != nil || len(steps) != 1 {
		t.Fatalf("install steps = %v, %v", steps, err)
	}
	for _, want := range []string{
		base64.StdEncoding.EncodeToString([]byte(hermesUnhookedAgentModule)),
		`>"$site/` + hermesUnhookedAgentModuleName + `.py"`,
		`printf 'import ` + hermesUnhookedAgentModuleName + `\n' >"$site/` + hermesUnhookedAgentModuleName + `.pth"`,
	} {
		if !strings.Contains(steps[0].Run, want) {
			t.Fatalf("the Hermes install does not write %q:\n%s", want, steps[0].Run)
		}
	}
	shParses(t, "Hermes install step", steps[0].Run)
}

// hermesTUIGatewayStandIn is the part of Hermes 0.19.0 the unhooked-agent
// shim works with: tui_gateway.server._make_agent, which the TUI's session
// calls build every agent through (by its module global), and the compute
// host, which calls it through the module.
var hermesTUIGatewayStandIn = map[string]string{
	"tui_gateway/__init__.py": "",
	"tui_gateway/server.py": `"""Stand-in tui_gateway.server."""
BUILT = []


def _make_agent(sid, key, session_id=None, **kwargs):
    BUILT.append(sid)
    return "agent"


def session_create(sid):
    return _make_agent(sid, "key")
`,
	"tui_gateway/compute_host.py": `from tui_gateway import server


def build(sid):
    return server._make_agent(sid, "key", session_id="s")
`,
}

// TestHermesUnhookedAgentShim runs the shim the Hermes image imports at
// every start against a stand-in tui_gateway: every way the TUI, dashboard
// and serve backend build an agent raises DefenseClaw's refusal, and the
// original _make_agent never runs; the patched module keeps its loader.
func TestHermesUnhookedAgentShim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the sandbox shims run in the Linux sandbox image, not on native Windows")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	for name, body := range hermesTUIGatewayStandIn {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), []byte(body))
	}
	writeFile(t, filepath.Join(dir, hermesUnhookedAgentModuleName+".py"), []byte(hermesUnhookedAgentModule))
	script := `import sys
sys.path.insert(0, sys.argv[1])
import ` + hermesUnhookedAgentModuleName + `
from tui_gateway import compute_host, server
assert type(server.__loader__).__name__ == "SourceFileLoader", server.__loader__
refused = 0
for build in (lambda: server.session_create("a"), lambda: compute_host.build("b"), lambda: server._make_agent("c", "k")):
    try:
        build()
    except RuntimeError as exc:
        assert str(exc).startswith("DefenseClaw: this Hermes runs the agent of its TUI"), exc
        refused += 1
print(refused, server.BUILT)
`
	out, err := exec.Command(python, "-I", "-c", script, dir).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "3 []" {
		t.Fatalf("shim run: %v\n%s", err, out)
	}
}

// TestHermesLauncherRefusesTheTUI: the launcher refuses, with the cause,
// the environment and configuration that start the pinned Hermes' TUI
// (HERMES_TUI=1; display.interface: tui in the home or a profile, as Hermes'
// YAML loader reads it, case and spaces aside) and starts with the others.
func TestHermesLauncherRefusesTheTUI(t *testing.T) {
	py := yamlInterpreter(t)
	for name, tc := range map[string]struct {
		env         []string
		rel, config string
		refusal     string // empty: Hermes must start
	}{
		"environment":            {env: []string{"HERMES_TUI=1"}, refusal: "HERMES_TUI=1 starts Hermes' TUI"},
		"environment off":        {env: []string{"HERMES_TUI=0"}},
		"environment tui theme":  {env: []string{"HERMES_TUI_THEME=light"}},
		"config":                 {rel: ".hermes/config.yaml", config: "display:\n  interface: tui\n", refusal: "config.yaml sets display.interface: tui"},
		"config spaced capitals": {rel: ".hermes/config.yaml", config: "display: {interface: ' TUI '}\n", refusal: "sets display.interface: tui"},
		"config escaped key":     {rel: ".hermes/config.yaml", config: "\"\\x64isplay\": {interface: tui}\n", refusal: "sets display.interface: tui"},
		"profile config":         {rel: ".hermes/profiles/work/config.yaml", config: "display:\n  interface: tui\n", refusal: "profiles/work/config.yaml sets display.interface: tui"},
		"config cli":             {rel: ".hermes/config.yaml", config: "display:\n  interface: cli\n"},
		"config display scalar":  {rel: ".hermes/config.yaml", config: "display: tui\n"},
		"config other keys":      {rel: ".hermes/config.yaml", config: "model: {default: m}\ndisplay: {skin: tui}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			l := newYAMLCheckedLauncher(t, Hermes, py)
			if tc.rel != "" {
				writeFile(t, filepath.Join(l.dir, filepath.FromSlash(tc.rel)), []byte(tc.config))
			}
			r := l.run(t, "", tc.env, "chat", "-q", "hi")
			if tc.refusal == "" {
				if r.exit != 0 || !r.started() {
					t.Fatalf("refused: exit %d %s", r.exit, r.output)
				}
				return
			}
			if r.exit != 2 || r.started() || !strings.Contains(r.output, "refusing to start Hermes: ") || !strings.Contains(r.output, tc.refusal) {
				t.Fatalf("exit %d started %t output %q, want a refusal saying %q", r.exit, r.started(), r.output, tc.refusal)
			}
		})
	}
}
