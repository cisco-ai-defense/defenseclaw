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
	"gopkg.in/yaml.v3"
)

// GAP-1036 / GAP-1078: the pinned Hermes builds the agent of its TUI,
// dashboard chat and serve backend without the shell hooks. The image keeps
// the refusal, the managed TUI pins and the shim only while its pin is such
// a release: the host warns about the same releases, and a pin past them
// must drop them.
func TestHermesImageRefusesTheUnhookedTUIOfItsPin(t *testing.T) {
	if got := connector.ResolveHookContract("hermes", Hermes.DefaultVersion); !strings.Contains(got.Warning, "hermes --tui") {
		t.Fatalf("the image pins Hermes %s, whose TUI runs the hooks (%+v): remove hermesUnhookedAgentModule, the launcher's --tui refusal "+
			"and the managed layer's TUI pins (HERMES_TUI=0, display.interface: cli in internal/gateway/connector/hermes_sandbox.go)",
			Hermes.DefaultVersion, got)
	}
	// The managed layer keeps every start but --tui on the hooked classic
	// interface: Hermes applies it over the environment, .env files and
	// user configs (GAP-1036 review).
	arts, err := Hermes.Provider.SandboxArtifacts(connector.SandboxRenderTarget{IngressPort: 18971, AgentVersion: Hermes.DefaultVersion})
	if err != nil {
		t.Fatal(err)
	}
	managed := map[string]string{}
	for _, f := range arts.Files {
		if f.Owner == connector.SandboxOwnerRoot {
			managed[f.Path] = string(f.Data)
		}
	}
	if env := managed[connector.HermesSandboxManagedEnvPath]; !strings.Contains(env, "\nHERMES_TUI=0\n") {
		t.Fatalf("the root-owned managed .env does not pin HERMES_TUI=0:\n%s", env)
	}
	var cfg struct {
		Display map[string]interface{} `yaml:"display"`
	}
	if err := yaml.Unmarshal([]byte(managed[connector.HermesSandboxManagedConfigPath]), &cfg); err != nil || cfg.Display["interface"] != "cli" {
		t.Fatalf("the root-owned managed config does not pin display.interface: cli (%v):\n%s", err, managed[connector.HermesSandboxManagedConfigPath])
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

// TestHermesLauncherLeavesTheInterfaceToTheManagedLayer (GAP-1036 review):
// the launcher refuses only --tui and its prefix (launcher_test.go). Hermes
// picks its TUI otherwise from HERMES_TUI=1 and display.interface: tui only
// on a terminal, and the image's managed layer pins both to the hooked
// classic interface over the environment, every .env and every config.yaml
// (TestHermesImageRefusesTheUnhookedTUIOfItsPin checks the pins), so these
// start Hermes, headless or not, set on or off, in the home or a profile.
func TestHermesLauncherLeavesTheInterfaceToTheManagedLayer(t *testing.T) {
	py := yamlInterpreter(t)
	tuiConfig := "display:\n  interface: tui\n"
	for name, tc := range map[string]struct {
		env       []string
		rel, data string
		args      []string
	}{
		"environment on":         {env: []string{"HERMES_TUI=1"}},
		"environment off":        {env: []string{"HERMES_TUI=0"}},
		"environment tui theme":  {env: []string{"HERMES_TUI_THEME=light"}},
		"env file off":           {rel: ".hermes/.env", data: "HERMES_TUI=0\n"},
		"env file on":            {rel: ".hermes/.env", data: "HERMES_TUI=1\n"},
		"env file quoted export": {rel: ".hermes/.env", data: "export HERMES_TUI=\"1\"\n"},
		"env file glued pair":    {rel: ".hermes/.env", data: "OPENAI_API_KEY=sk-xHERMES_TUI=1\n"},
		"op env file":            {rel: ".hermes/.op.env", data: "HERMES_TUI=1\n"},
		"profile env file":       {rel: ".hermes/profiles/work/.env", data: "HERMES_TUI=1\n", args: []string{"-p", "work", "chat"}},
		"config headless query":  {rel: ".hermes/config.yaml", data: tuiConfig},
		"config bare":            {rel: ".hermes/config.yaml", data: tuiConfig, args: []string{}},
		"config with --cli":      {rel: ".hermes/config.yaml", data: tuiConfig, args: []string{"chat", "--cli"}},
		"config spaced capitals": {rel: ".hermes/config.yaml", data: "display: {interface: ' TUI '}\n"},
		"profile config":         {rel: ".hermes/profiles/work/config.yaml", data: tuiConfig, args: []string{"--profile", "work"}},
		"config cli":             {rel: ".hermes/config.yaml", data: "display:\n  interface: cli\n"},
	} {
		t.Run(name, func(t *testing.T) {
			l := newYAMLCheckedLauncher(t, Hermes, py)
			if tc.rel != "" {
				writeFile(t, filepath.Join(l.dir, filepath.FromSlash(tc.rel)), []byte(tc.data))
			}
			args := tc.args
			if args == nil {
				args = []string{"chat", "-q", "hi"}
			}
			if r := l.run(t, "", tc.env, args...); r.exit != 0 || !r.started() {
				t.Fatalf("refused: exit %d %s", r.exit, r.output)
			}
		})
	}
}
