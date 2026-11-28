// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// renderedShellFunction is the text of function name in a rendered hook
// script, from its first line to the closing brace at column one.
func renderedShellFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("the rendered hook defines no %s", name)
	}
	end := strings.Index(script[start+1:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s has no closing brace", name)
	}
	return script[start+1 : start+1+end+3]
}

// GAP-1770: the shell Codex hook's own blocks (an outage or a failure it
// fails closed on, a gateway block without codex_output) are the native
// runner's answers, for every contract and event: the per-user and the
// standalone managed render are held to the table emitCodexBlock is held to.
// The shell hook exited 2 with nothing on stderr for a Stop or SubagentStop
// block, which Codex reads as a hook failure, so the reason never reached the
// turn; it also exited 2 for SessionEnd, which the native runner lets end.
func TestCodexShellClosedAnswerMatchesTheNativeRunner(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "codex_block_answers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Reason  string `json:"reason"`
		Answers []struct {
			Contract string `json:"contract"`
			Event    string `json:"event"`
			Exit     int    `json:"exit"`
			Stdout   string `json:"stdout"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Answers) == 0 || table.Reason == "" {
		t.Fatal("empty answer table")
	}
	for _, render := range []struct {
		name string
		opts SetupOpts
	}{
		{"per-user", SetupOpts{APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token"}},
		{"managed", SetupOpts{APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", ManagedEnterprise: true}},
	} {
		t.Run(render.name, func(t *testing.T) {
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			render.opts.DataDir = home
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, render.opts, NewCodexConnector()); err != nil {
				t.Fatal(err)
			}
			script, err := os.ReadFile(filepath.Join(hookDir, "codex-hook.sh"))
			if err != nil {
				t.Fatal(err)
			}
			funcs := renderedShellFunction(t, string(script), "codex_event_can_control") +
				renderedShellFunction(t, string(script), "codex_closed_answer")
			for _, row := range table.Answers {
				cmd := exec.Command("bash", "-c", funcs+`_DC_CODEX_CONTRACT="$1"; _DC_CODEX_EVENT="$2"; codex_closed_answer "$3"`,
					"answer", row.Contract, row.Event, table.Reason)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				code := 0
				if err := cmd.Run(); err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						t.Fatal(err)
					}
					code = exit.ExitCode()
				}
				if code != row.Exit || stdout.String() != row.Stdout {
					t.Errorf("%q %s: exit %d stdout %q stderr %q, want exit %d stdout %q",
						row.Contract, row.Event, code, stdout.String(), stderr.String(), row.Exit, row.Stdout)
				}
			}
		})
	}
}
