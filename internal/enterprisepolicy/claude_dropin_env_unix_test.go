// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0465: Claude Code applies the managed env block to every
// process it starts, the Bash tool shell included, and that shell sources
// Claude Code's shell snapshot, which runs `set -o onecmd`. A bash that found
// SHELLOPTS in its environment, even as an empty value, exports it, so an
// older drop-in that pinned it made every script run its first command only.
// This starts a script the way the tool shell does, with the rendered drop-in
// env, and checks that the whole script runs.
func TestClaudeDropInEnvLetsBashToolScriptsRun(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	opts := testOptions(t)
	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	script := filepath.Join(dir, "notes.sh")
	body := "#!" + bash + "\necho one >> \"$1\"\necho two >> \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if _, managed := doc.Env[name]; !managed && name != "SHELLOPTS" && name != "BASHOPTS" && name != "BASH_ENV" {
			env = append(env, kv)
		}
	}
	for name, value := range doc.Env {
		env = append(env, name+"="+value)
	}
	// The snapshot's shell options line, then the command the model asked for.
	cmd := exec.Command(bash, "-c", "set -o onecmd; \"$0\" \"$1\"; set -o monitor", script, out)
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tool shell: %v: %s", err, output)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "one\ntwo\n" {
		t.Fatalf("script output = %q, want both lines: the drop-in env %v carries the tool shell's options into the script", got, doc.Env)
	}
}

// The same native command runs for an ordinary session and for one whose
// shell options would stop a shell-form handler on macOS or RHEL.
func TestClaudeManagedExecFormIgnoresShellOptions(t *testing.T) {
	opts := testOptions(t)
	opts.HookBinary = "/bin/echo"
	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	handler := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	for _, shellopts := range []string{"", "noexec"} {
		var cmd *exec.Cmd
		if rawArgs, ok := handler["args"].([]any); ok {
			args := make([]string, 0, len(rawArgs))
			for _, raw := range rawArgs {
				args = append(args, raw.(string))
			}
			cmd = exec.Command(handler["command"].(string), args...)
		} else {
			// Bash in sh mode is the shell on the affected managed hosts.
			cmd = exec.Command("/bin/bash", "--posix", "-c", handler["command"].(string))
		}
		var env []string
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			if name != "SHELLOPTS" {
				env = append(env, entry)
			}
		}
		if shellopts != "" {
			env = append(env, "SHELLOPTS="+shellopts)
		}
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		if err != nil || string(output) != "hook --connector claudecode --enterprise-managed\n" {
			t.Fatalf("SHELLOPTS=%q: output %q, error %v", shellopts, output, err)
		}
	}
}

// rel-1-0-6:GAP-0465 review finding 5: an administrator's own SHELLOPTS ""
// in a managed source recreates the bug, so verify names it.
func TestClaudeVerifyNamesAnEmptyManagedShellopts(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	dir := claudeDir(t, opts)
	writeFile(t, filepath.Join(dir, "managed-settings.json"), `{"env": {"SHELLOPTS": ""}}`+"\n")
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	details := strings.Join(state.Details, "\n")
	if !strings.Contains(details, "managed-settings.json sets env SHELLOPTS to \"\", which breaks Bash tool scripts") {
		t.Fatalf("details lack the empty SHELLOPTS note:\n%s", details)
	}
}

func TestClaudeVerifyReportsManagedShelloptsNoexec(t *testing.T) {
	for _, tc := range []struct {
		name   string
		value  string
		higher bool
		want   bool
	}{
		{"file source", "braceexpand:noexec", false, true},
		{"managed preferences", "noexec:braceexpand", true, true},
		{"ordinary options", "braceexpand:hashall", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = "darwin"
			withHigherSources(t)
			if _, err := (claudeTarget{}).Reconcile(opts); err != nil {
				t.Fatal(err)
			}
			body := `{"env":{"SHELLOPTS":"` + tc.value + `"}}`
			if tc.higher {
				withHigherSources(t, higherSource(t, "managed preferences", body))
			} else {
				writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json"), body)
			}
			state, err := (claudeTarget{}).Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			details := strings.Join(state.Details, "\n")
			got := strings.Contains(details, "sets env SHELLOPTS with noexec")
			if got != tc.want {
				t.Fatalf("noexec detail = %v, want %v: %s", got, tc.want, details)
			}
		})
	}
}
