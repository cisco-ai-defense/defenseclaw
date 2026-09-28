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

package image

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// omnigentSim plays OmniGent in the probe container: a headless or
// interactive run posts the policy phases to the sink, unless the
// interactive run crashes before its REPL starts (the first-launch theme
// picker of R2-79).
type omnigentSim struct {
	t          *testing.T
	port       int
	ttyCrashes bool
	scripts    []string
}

func (s *omnigentSim) handle(args []string) (string, int) {
	argv := parseProbeArgv(args)
	script := argv.script
	s.scripts = append(s.scripts, script)
	interactive := strings.Contains(script, ptyDriver)
	if interactive && s.ttyCrashes {
		return "::rc=1\n::side-effect=absent\n::output-begin\nUserConfigError: Failed to write TUI user config\n::output-end\n", 0
	}
	command := builtinAllowPrompt
	if strings.Contains(script, builtinBlockPrompt) {
		command = builtinBlockPrompt
	}
	blocked := false
	for _, event := range requiredHookEvents["omnigent"] {
		body, err := postHook(http.DefaultClient, "http://"+net.JoinHostPort(argv.host, strconv.Itoa(s.port))+"/api/v1/omnigent/policy",
			argv.env[connector.SandboxTokenEnv], "k-"+event, map[string]interface{}{"hook_event_name": event, "tool_input": map[string]string{"command": command}})
		if err != nil {
			s.t.Errorf("post %s: %v", event, err)
			return "", 1
		}
		var verdict struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal([]byte(body), &verdict)
		blocked = blocked || (event == "PreToolUse" && verdict.Action == "block")
	}
	out := "::rc=0\n"
	if strings.Contains(script, "::side-effect=") {
		out += simSideEffect(!blocked)
	}
	return out + "::output-begin\nok\n::output-end\n", 0
}

// TestHookFireProbeStartsOmniGentOnATerminal pins that the probe also runs
// OmniGent's TUI on a terminal (its first-launch theme picker never runs
// headless) and fails the image when that launch does not reach its hooks.
func TestHookFireProbeStartsOmniGentOnATerminal(t *testing.T) {
	saved, had := hostileSettingsPlans["omnigent"]
	delete(hostileSettingsPlans, "omnigent")
	t.Cleanup(func() {
		if had {
			hostileSettingsPlans["omnigent"] = saved
		}
	})
	for _, crash := range []bool{false, true} {
		c := hookFireContextFor(t, harness.OmniGent)
		sim := &omnigentSim{t: t, port: c.Spec.IngressPort, ttyCrashes: crash}
		b := &Builder{Docker: &fakeDocker{handler: func(args []string, _ []byte) (string, int) { return sim.handle(args) }}}
		res, err := b.HookFireProbe(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
		var tty *HookFireRun
		for i := range res.Runs {
			if res.Runs[i].Scenario == ScenarioInteractive {
				tty = &res.Runs[i]
			}
		}
		if tty == nil {
			t.Fatalf("crash=%t: no interactive run: %+v (%v)", crash, res.Runs, err)
		}
		last := sim.scripts[len(sim.scripts)-1]
		if !strings.Contains(last, harness.OmniGentLauncherPath) || strings.Contains(last, "'-p'") ||
			!strings.Contains(last, shQuote(builtinAllowPrompt)) || !strings.Contains(last, " '/exit' ") {
			t.Fatalf("interactive run script does not type the prompt into the TUI:\n%s", last)
		}
		switch {
		case !crash && err != nil:
			t.Fatalf("HookFireProbe: %v", err)
		case crash && (!errors.Is(err, ErrHooksNotFired) || !strings.Contains(err.Error(), "in the interactive (terminal) launch, the harness exited 1") ||
			!strings.Contains(err.Error(), "hook UserPromptSubmit never fired")):
			t.Fatalf("a crashing TUI passed the probe: %v", err)
		}
	}
}

// runPTYDriver runs the probe's pty driver against a stand-in TUI, a bash
// script with this body, and returns the driver's output, what it logged
// of the TUI and its error.
func runPTYDriver(t *testing.T, body string) (string, string, error) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	tui := filepath.Join(dir, "tui")
	if err := os.WriteFile(tui, []byte("#!/bin/bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "out")
	cmd := exec.Command(python, "-I", "-S", "-c", ptyDriver, "20", "hello probe", interactiveDoneText, "/exit", tui)
	cmd.Env = append(os.Environ(), "DC_HOOKFIRE_OUT="+logPath)
	out, err := cmd.CombinedOutput()
	logged, _ := os.ReadFile(logPath)
	return string(out), string(logged), err
}

func wantDriverExit(t *testing.T, err error, out string, code int) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("driver = %v, want the TUI's exit status %d\n%s", err, code, out)
	}
}

// TestPTYDriverTypesThePromptAndQuits runs the probe's pty driver against a
// stand-in TUI: it must wait for the prompt, type the scenario prompt, wait
// for the closing text across line breaks, type quit and pass on the exit
// status.
func TestPTYDriverTypesThePromptAndQuits(t *testing.T) {
	out, logged, err := runPTYDriver(t, "printf 'ready> '\nIFS= read -r line\n[ \"$line\" = \"hello probe\" ] || exit 3\n"+
		"printf 'working\\r\\nDone: the marker\\r\\n file was written.\\r\\n> '\nIFS= read -r q\n[ \"$q\" = /exit ] && exit 7\nexit 4\n")
	wantDriverExit(t, err, out, 7)
	if !strings.Contains(logged, "ready> ") || !strings.Contains(logged, "file was written") {
		t.Fatalf("driver log = %q", logged)
	}
}

// The driver exited 125 for a TUI that had quit (a loaded Linux host): the
// terminal closes as the TUI exits, a moment before the kernel lets its
// status be collected, and the driver's wait counted reads of the closed
// terminal, which return at once, rather than time. A TUI that lets go of
// its terminal a second before it exits still has its own status passed
// on, not a signal's.
func TestPTYDriverWaitsForTheStatusAfterTheTerminalCloses(t *testing.T) {
	out, _, err := runPTYDriver(t, "printf 'ready> '\nIFS= read -r line\n"+
		"printf 'Done: the marker file was written.\\r\\n> '\nIFS= read -r q\n"+
		"exec </dev/null >/dev/null 2>&1\nsleep 1\n[ \"$q\" = /exit ] && exit 7\nexit 4\n")
	wantDriverExit(t, err, out, 7)
}
