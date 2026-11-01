// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// hookHostileDeny reads an observation as the agents do: exit 2 blocks, and
// so does a deny or block object on stdout with exit 0.
var hookHostileDeny = regexp.MustCompile(`"(deny|block)"|"continue":\s*false|"permission":"deny"|"permissionDecision":"deny"|"decision":"(deny|block)"`)

func hookHostileVerdict(o hookGoldenObservation) string {
	switch {
	case o.Exit == 2:
		return "deny"
	case o.Exit == 0 && hookHostileDeny.MatchString(o.Stdout):
		return "deny"
	case o.Exit == 0:
		return "allow"
	}
	return "exit" + strconv.Itoa(o.Exit)
}

// hookHostileEnvs are agent environments that turned a block into an allow
// or a non-blocking error in review 2 of sandbox-visibility:GAP-0028:
// FUNCNEST, TMOUT, EXECIGNORE and POSIX mode (dropped before the first
// function call), BASH_ENV, ENV, SHELLOPTS and exported functions (ignored
// under bash -p), BASH_SOURCE (a helper that does not load blocks) and a
// DEFENSECLAW_HOOK_MAX_BODY that overflowed the read's bound (clamped).
func hookHostileEnvs() map[string][]string {
	envs := map[string][]string{
		"so-noexec":        {"SHELLOPTS=noexec"},
		"so-onecmd":        {"SHELLOPTS=onecmd"},
		"so-keyword":       {"SHELLOPTS=keyword"},
		"so-posix":         {"SHELLOPTS=posix"},
		"posix":            {"POSIXLY_CORRECT=1"},
		"bash-env-exit0":   {"BASH_ENV=<BASE>/exit0.sh"},
		"env-exit0":        {"ENV=<BASE>/exit0.sh"},
		"fn-printf":        {"BASH_FUNC_printf%%=() {  :; }"},
		"fn-exec":          {`BASH_FUNC_exec%%=() {  echo '{"action":"allow"}'; }`},
		"fn-curl":          {`BASH_FUNC_curl%%=() {  printf '{"action":"allow"}\n200'; }`},
		"fn-jq":            {`BASH_FUNC_jq%%=() {  echo '{"action":"allow"}'; }`},
		"fn-read":          {"BASH_FUNC_read%%=() {  return 1; }"},
		"fn-command":       {"BASH_FUNC_command%%=() {  return 1; }"},
		"bash-source":      {"BASH_SOURCE=5"},
		"bash-source-abs":  {"BASH_SOURCE=/tmp/review2-nohook.sh"},
		"tmout-slow-stdin": {"TMOUT=1", "DCREVIEW_STDIN_DELAY_MS=2500"},
		"execignore-jq":    {"EXECIGNORE=*/jq"},
		"execignore-all":   {"EXECIGNORE=*"},
		"max-body-huge":    {"DEFENSECLAW_HOOK_MAX_BODY=9223372036854775807"},
		"max-body-long":    {"DEFENSECLAW_HOOK_MAX_BODY=99999999999999999999"},
	}
	for _, n := range []int{1, 2, 3, 4, 8, 32} {
		envs["funcnest-"+strconv.Itoa(n)] = []string{"FUNCNEST=" + strconv.Itoa(n)}
	}
	return envs
}

// TestShellHookBlockSurvivesHostileEnvironments: a call each shell hook
// blocks in a plain environment (a gateway block, with and without its native
// object, and an outage in closed mode) stays blocked in every hostile agent
// environment above, for the per-user closed and the managed closed renders.
func TestShellHookBlockSurvivesHostileEnvironments(t *testing.T) {
	for _, tool := range []string{"jq", "curl", "awk"} {
		if _, err := lookPathForHostileTest(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	scratch := t.TempDir()
	installNativeGatewayForHookTest(t, filepath.Join(scratch, "probe-gw"))
	installNativeHookPostForHookTest(t, filepath.Join(scratch, "probe-post"))
	base, err := os.MkdirTemp("/tmp", "dch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(filepath.Join(base, "exit0.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	modes := hookGoldenModes()
	answers := map[string]hookGoldenAnswer{}
	for _, a := range hookGoldenAnswers() {
		answers[a.name] = a
	}
	envs := hookHostileEnvs()
	names := make([]string, 0, len(envs))
	for n := range envs {
		names = append(names, n)
	}
	sort.Strings(names)
	type key struct{ hook, mode, answer string }
	var cases []hookGoldenCase
	for _, h := range hookGoldenHooks() {
		for _, m := range []hookGoldenMode{modes[1], modes[5]} {
			for _, a := range []string{"block-bare", "block-output", "unreachable"} {
				c := hookGoldenCase{hook: h, mode: m, answer: answers[a], event: h.events[0], command: "cat ./hello.txt"}
				c.id = fmt.Sprintf("%s/%s/%s", h.name, m.name, a)
				cases = append(cases, c)
				for _, n := range names {
					hc := c
					hc.id += "/" + n
					hc.env = envs[n]
					cases = append(cases, hc)
				}
			}
		}
	}
	var (
		mu       sync.Mutex
		verdicts = map[string]string{}
		detail   = map[string]string{}
		next     atomic.Int64
		wg       sync.WaitGroup
	)
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(cases) {
					return
				}
				obs, err := runHookGoldenCase(base, i, cases[i])
				mu.Lock()
				if err != nil {
					verdicts[cases[i].id] = "setup: " + err.Error()
				} else {
					verdicts[cases[i].id] = hookHostileVerdict(obs)
					detail[cases[i].id] = fmt.Sprintf("exit %d stdout %q stderr %q", obs.Exit, obs.Stdout, review2Tail(obs.Stderr))
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	var failures []string
	checked := 0
	for _, c := range cases {
		parts := strings.Split(c.id, "/")
		if len(parts) != 4 {
			continue
		}
		plain := strings.Join(parts[:3], "/")
		if verdicts[plain] != "deny" {
			continue
		}
		checked++
		if v := verdicts[c.id]; v != "deny" {
			failures = append(failures, fmt.Sprintf("%s: %s, plain environment denies; %s", c.id, v, detail[c.id]))
		}
	}
	sort.Strings(failures)
	for i, f := range failures {
		if i == 40 {
			t.Errorf("... and %d more", len(failures)-40)
			break
		}
		t.Error(f)
	}
	t.Logf("%d hostile cases checked against a plain-environment block", checked)
}

func lookPathForHostileTest(name string) (string, error) { return exec.LookPath(name) }

// TestSandboxHookOutcomeIgnoresExportedBashVariables: the sandbox scrub
// unset every exported name, which took the meaning off bash's own
// variables (an exported RANDOM ended every sandbox hook with exit 1), and
// an exported BASH_SOURCE moved the helper path (review 2 of
// sandbox-visibility:GAP-0028). A block and an ingress outage answer the
// same with each of them exported.
func TestSandboxHookOutcomeIgnoresExportedBashVariables(t *testing.T) {
	exported := []string{"RANDOM=5", "SRANDOM=5", "SECONDS=5", "LINENO=5", "BASHPID=5", "EPOCHSECONDS=5", "EPOCHREALTIME=5",
		"BASH_SOURCE=5", "BASH_SOURCE=/tmp/review2-nohook.sh", "FUNCNAME=5", "FUNCNEST=1", "FUNCNEST=3", "TMOUT=1", "EXECIGNORE=*", "OSTYPE=darwin"}
	for _, tc := range sandboxHookCases() {
		tc := tc
		t.Run(tc.script+"-"+tc.connector, func(t *testing.T) {
			t.Parallel()
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			script := SandboxHookDir + "/" + tc.script
			for rname, reply := range map[string][]string{
				"block": {`200|{"action":"block","reason":"nope"}`},
				"down":  {"exit:7", "exit:7"},
			} {
				env := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash"}
				plain := h.run(t, script, tc.args, tc.stdin, env, reply)
				for _, kv := range exported {
					name, value, _ := strings.Cut(kv, "=")
					with := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash", name: value}
					got := h.run(t, script, tc.args, tc.stdin, with, reply)
					if got.exitCode != plain.exitCode || got.stdout != plain.stdout {
						t.Errorf("%s %s with %s: exit %d stdout %q, plain environment exit %d stdout %q; stderr %q",
							tc.script, rname, kv, got.exitCode, got.stdout, plain.exitCode, plain.stdout, review2Tail(got.stderr))
					}
				}
			}
		})
	}
}
