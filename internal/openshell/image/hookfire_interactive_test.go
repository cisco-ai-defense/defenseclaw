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
	"bytes"
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
	host, token := "", ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--add-host":
			if v, ok := strings.CutPrefix(args[i+1], connector.SandboxIngressHost+":"); ok {
				host = v
			}
		case "-e":
			if v, ok := strings.CutPrefix(args[i+1], connector.SandboxTokenEnv+"="); ok {
				token = v
			}
		}
	}
	script := args[len(args)-1]
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
		payload, _ := json.Marshal(map[string]interface{}{"hook_event_name": event, "tool_input": map[string]string{"command": command}})
		req, _ := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort(host, strconv.Itoa(s.port))+"/api/v1/omnigent/policy", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-DefenseClaw-Hook-Idempotency-Key", "k-"+event)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.t.Errorf("post %s: %v", event, err)
			return "", 1
		}
		var verdict struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&verdict)
		resp.Body.Close()
		blocked = blocked || (event == "PreToolUse" && verdict.Action == "block")
	}
	out := "::rc=0\n"
	if strings.Contains(script, "::side-effect=") {
		if blocked {
			out += "::side-effect=absent\n"
		} else {
			out += "::side-effect=present\n"
		}
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

// TestPTYDriverTypesThePromptAndQuits runs the probe's pty driver against a
// stand-in TUI: it must wait for the prompt, type the scenario prompt, wait
// for the closing text across line breaks, type quit and pass on the exit
// status.
func TestPTYDriverTypesThePromptAndQuits(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	tui := filepath.Join(dir, "tui")
	body := "#!/bin/bash\nprintf 'ready> '\nIFS= read -r line\n[ \"$line\" = \"hello probe\" ] || exit 3\n" +
		"printf 'working\\r\\nDone: the marker\\r\\n file was written.\\r\\n> '\nIFS= read -r q\n[ \"$q\" = /exit ] && exit 7\nexit 4\n"
	if err := os.WriteFile(tui, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "out")
	cmd := exec.Command(python, "-I", "-S", "-c", ptyDriver, "20", "hello probe", interactiveDoneText, "/exit", tui)
	cmd.Env = append(os.Environ(), "DC_HOOKFIRE_OUT="+logPath)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("driver = %v, want the TUI's exit status 7\n%s", err, out)
	}
	logged, _ := os.ReadFile(logPath)
	if !strings.Contains(string(logged), "ready> ") || !strings.Contains(string(logged), "file was written") {
		t.Fatalf("driver log = %q", logged)
	}
}
