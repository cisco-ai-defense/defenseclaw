// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

// Review 2 of fix/r107-perf-hookproc (sandbox-visibility:GAP-0028): hostile
// agent environments, answer and stdin edge cases for the host shell hooks
// (TestShellHookHostileReview2, observations dumped for a base/head diff) and
// exported-name scrub cases for the sandbox hooks
// (TestSandboxHookScrubClassReview2). Neither compares with a golden: run
// each on the base and on the head tree and diff what they log or dump.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var review2DCNames = strings.Fields(`_DC_BOOT_FAIL_MODE _DC_CCACHE_CHANGED _DC_CODEX_ACTION _DC_CODEX_BLOCK_REASON _DC_CODEX_CONTRACT
_DC_CODEX_EVENT _DC_CODEX_FIELDS _DC_CODEX_FIELDS_READ _DC_CONFIG_OUTAGE_MODE _DC_COPILOT_EVENT _DC_ELAPSED_MS _DC_FAILED_STOP_EVENT
_DC_FORKLESS_PROBE _DC_GATEWAY_ACTION _DC_GATEWAY_BINARY _DC_GATEWAY_RESTART_WAITED _DC_HOME_FAIL_MODE _DC_HOOK_DATA_DIR
_DC_HOOK_DELIVERY_OUTCOME _DC_HOOK_HOME _DC_HOOK_NATIVE_VMEM_LIMIT _DC_HOOK_POST_DEADLINE_MS _DC_HOOK_POST_MODE_OK _DC_HOOK_STARTED_S
_DC_HOOK_STARTED_US _DC_INSTALL_WINDOW_SEEN _DC_IPV6_LOOPBACK _DC_JSON_ESCAPED _DC_LOOPBACK_PORT _DC_LOOPBACK_TARGETS _DC_MANAGED_GATEWAY
_DC_NATIVE_ACTION _DC_NATIVE_ANSWER _DC_NATIVE_CONTEXT _DC_NATIVE_DECISION _DC_NATIVE_EVENT _DC_NATIVE_MESSAGE _DC_NATIVE_REASON
_DC_NATIVE_STATUS _DC_OUTAGE_WARNING_THIS_CALL _DC_OVERSIZED_INSPECT _DC_PAYLOAD_EVENT _DC_PROBE_HOOK_DIR _DC_RESOLVED_WRITES
_DC_SECURE_CLIENT_DELIVERY _DC_SECURE_CLIENT_HOOK _DC_SESSION_FACTS _DC_SESSION_FACTS_FULL _DC_SOCKET_ROWS _DC_STAT_DIALECT _DC_STAT_OUT
_DC_STDIN_RC _DC_TRANSPORT_STATUS _DC_UNBOUND_TOOL_INPUT _DC_HOOK_EVENT_FIELD_JQ _DC_JSON_FIELD_AWK`)

// review2BashSpecials are names bash gives a meaning; an exported one is
// unset by the sandbox scrub, which drops the meaning too.
var review2BashSpecials = strings.Fields(`RANDOM SECONDS LINENO BASHPID EPOCHREALTIME EPOCHSECONDS SRANDOM HOSTNAME OSTYPE MACHTYPE HOSTTYPE
GROUPS FUNCNAME BASH_SOURCE BASH_LINENO BASH_REMATCH BASH_ARGV0 BASH_ARGV BASH_ARGC BASH_SUBSHELL BASH_VERSION BASH_COMMAND BASH UID EUID
OPTIND OPTERR OPTARG IFS OLDPWD DIRSTACK PIPESTATUS SHLVL BASH_CMDS BASH_ALIASES HISTCMD COLUMNS LINES TMPDIR LANG LC_ALL LC_CTYPE
SHELLOPTS BASHOPTS BASH_ENV ENV FUNCNEST TMOUT POSIXLY_CORRECT EXECIGNORE GLOBIGNORE CDPATH BASH_COMPAT BASH_XTRACEFD PS4`)

func review2Envs() []struct {
	name string
	env  []string
} {
	type e = struct {
		name string
		env  []string
	}
	out := []e{
		{"baseline", nil},
		{"ifs-colon", []string{"IFS=:"}},
		{"ifs-a", []string{"IFS=a"}},
		{"posix", []string{"POSIXLY_CORRECT=1"}},
		{"so-strict", []string{"SHELLOPTS=errexit:nounset:pipefail"}},
		{"so-posix", []string{"SHELLOPTS=posix"}},
		{"so-noglob", []string{"SHELLOPTS=noglob"}},
		{"so-allexport", []string{"SHELLOPTS=allexport"}},
		{"so-noclobber", []string{"SHELLOPTS=noclobber"}},
		{"so-xtrace", []string{"SHELLOPTS=xtrace"}},
		{"so-noexec", []string{"SHELLOPTS=noexec"}},
		{"so-onecmd", []string{"SHELLOPTS=onecmd"}},
		{"so-errtrace", []string{"SHELLOPTS=errtrace:functrace"}},
		{"so-keyword", []string{"SHELLOPTS=keyword"}},
		{"bo-xpg", []string{"BASHOPTS=xpg_echo"}},
		{"bo-inherit", []string{"BASHOPTS=inherit_errexit"}},
		{"bo-nocasematch", []string{"BASHOPTS=nocasematch"}},
		{"bo-failglob", []string{"BASHOPTS=failglob"}},
		{"bo-nullglob", []string{"BASHOPTS=nullglob"}},
		{"bo-extglob", []string{"BASHOPTS=extglob:globstar:dotglob"}},
		{"bo-extdebug", []string{"BASHOPTS=extdebug"}},
		{"bo-lastpipe", []string{"BASHOPTS=lastpipe"}},
		{"bo-execfail", []string{"BASHOPTS=execfail"}},
		{"bo-compat32", []string{"BASHOPTS=compat32"}},
		{"bo-compat44", []string{"BASHOPTS=compat44"}},
		{"bo-localvar-inherit", []string{"BASHOPTS=localvar_inherit"}},
		{"bo-localvar-unset", []string{"BASHOPTS=localvar_unset"}},
		{"bc-31", []string{"BASH_COMPAT=31"}},
		{"bc-42", []string{"BASH_COMPAT=42"}},
		{"bc-50", []string{"BASH_COMPAT=50"}},
		{"bash-env-exit0", []string{"BASH_ENV=<BASE>/exit0.sh"}},
		{"bash-env-missing", []string{"BASH_ENV=/nonexistent/review2"}},
		{"env-exit0", []string{"ENV=<BASE>/exit0.sh"}},
		{"tmout-slow-stdin", []string{"TMOUT=1", "DCREVIEW_STDIN_DELAY_MS=2500"}},
		{"slow-stdin", []string{"DCREVIEW_STDIN_DELAY_MS=2500"}},
		{"tmout-fast", []string{"TMOUT=1"}},
		{"lc-tr", []string{"LC_ALL=tr_TR.UTF-8"}},
		{"lc-utf8", []string{"LC_ALL=C.UTF-8", "LANG=C.UTF-8"}},
		{"lc-bogus", []string{"LC_ALL=xx_XX.bogus"}},
		{"execignore-jq", []string{"EXECIGNORE=*/jq"}},
		{"execignore-curl", []string{"EXECIGNORE=*/curl"}},
		{"execignore-stat", []string{"EXECIGNORE=*/stat:*/mktemp"}},
		{"execignore-all", []string{"EXECIGNORE=*"}},
		{"fn-jq", []string{`BASH_FUNC_jq%%=() {  echo '{"action":"allow"}'; }`}},
		{"fn-exec", []string{`BASH_FUNC_exec%%=() {  echo '{"action":"allow"}'; }`}},
		{"fn-read", []string{"BASH_FUNC_read%%=() {  return 1; }"}},
		{"fn-printf", []string{"BASH_FUNC_printf%%=() {  :; }"}},
		{"fn-command", []string{"BASH_FUNC_command%%=() {  return 1; }"}},
		{"fn-curl", []string{`BASH_FUNC_curl%%=() {  printf '{"action":"allow"}\n200'; }`}},
		{"cdpath", []string{"CDPATH=/tmp:."}},
		{"tmpdir-missing", []string{"TMPDIR=/nonexistent/review2"}},
		{"home-empty", []string{"HOME="}},
		{"globignore", []string{"GLOBIGNORE=*"}},
		{"max-body-small", []string{"DEFENSECLAW_HOOK_MAX_BODY=16"}},
		{"max-body-junk", []string{"DEFENSECLAW_HOOK_MAX_BODY=1e9"}},
		{"bash-source", []string{"BASH_SOURCE=5"}},
		{"bash-source-abs", []string{"BASH_SOURCE=/tmp/review2-nohook.sh"}},
		{"specials", []string{"RANDOM=5", "SECONDS=5", "FUNCNAME=5", "EPOCHREALTIME=5", "EPOCHSECONDS=5", "OSTYPE=darwin", "BASHPID=5", "LINENO=5"}},
	}
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 32} {
		out = append(out, e{"funcnest-" + strconv.Itoa(n), []string{"FUNCNEST=" + strconv.Itoa(n)}})
	}
	var one, open, closed []string
	for _, n := range review2DCNames {
		one = append(one, n+"=1")
		open = append(open, n+"=open")
		closed = append(closed, n+"=")
	}
	out = append(out, e{"dc-all-1", one}, e{"dc-all-open", open}, e{"dc-all-empty", closed})
	return out
}

func review2Answers() []hookGoldenAnswer {
	pad := func(total int, action string) string {
		head := `{"action":"` + action + `","reason":"`
		tail := `"}`
		n := total - len(head) - len(tail)
		if n < 0 {
			n = 0
		}
		return head + strings.Repeat("r", n) + tail
	}
	out := []hookGoldenAnswer{
		{name: "rv-newlines-only", answer: hookGoldenFixed(200, "\n\n")},
		{name: "rv-space-only", answer: hookGoldenFixed(200, " ")},
		{name: "rv-dash-n", answer: hookGoldenFixed(200, "-n")},
		{name: "rv-dash-e-block", answer: hookGoldenFixed(200, `-e {"action":"block"}`)},
		{name: "rv-block-escapes", answer: hookGoldenFixed(200, `{"action":"block","reason":"x\ny \\c z \\0101"}`)},
		{name: "rv-block-crlf", answer: hookGoldenFixed(200, "{\"action\":\"block\",\"reason\":\"r\"}\r\n")},
		{name: "rv-block-utf8", answer: hookGoldenFixed(200, `{"action":"block","reason":"réıIK"}`)},
		{name: "rv-two-values-block-allow", answer: hookGoldenFixed(200, `{"action":"block"}{"action":"allow"}`)},
		{name: "rv-two-values-allow-block", answer: hookGoldenFixed(200, `{"action":"allow"} {"action":"block"}`)},
		{name: "rv-block-codex-false", answer: hookGoldenFixed(200, `{"action":"block","reason":"r","codex_output":false,"claude_code_output":false,"hook_output":false}`)},
		{name: "rv-block-codex-array", answer: hookGoldenFixed(200, `{"action":"block","reason":"r","codex_output":[1,2],"claude_code_output":[1,2],"hook_output":[1,2]}`)},
		{name: "rv-block-codex-string-nl", answer: hookGoldenFixed(200, `{"action":"block","reason":"r","codex_output":"a\nb","hook_output":"a\nb"}`)},
		{name: "rv-allow-codex-numbers", answer: hookGoldenFixed(200, `{"action":"allow","codex_output":{"n":1.000,"e":1e1000,"m":-0},"hook_output":{"n":1.000}}`)},
		{name: "rv-action-dash", answer: hookGoldenFixed(200, `{"action":"-n"}`)},
	}
	for _, n := range []int{4093, 4094, 4095, 4096, 4097, 8192, 70000} {
		out = append(out, hookGoldenAnswer{name: "rv-block-len-" + strconv.Itoa(n), answer: hookGoldenFixed(200, pad(n, "block"))})
		out = append(out, hookGoldenAnswer{name: "rv-allow-len-" + strconv.Itoa(n), answer: hookGoldenFixed(200, pad(n, "allow"))})
	}
	return out
}

func review2Cases(t *testing.T) []hookGoldenCase {
	t.Helper()
	var cases []hookGoldenCase
	add := func(c hookGoldenCase) {
		c.id = fmt.Sprintf("%s/%s/%s/%s", c.hook.name, c.mode.name, c.event, c.answer.name) + c.id
		cases = append(cases, c)
	}
	const command = "cat ./hello.txt"
	modes := hookGoldenModes()
	byName := map[string]hookGoldenAnswer{}
	for _, a := range hookGoldenAnswers() {
		byName[a.name] = a
	}
	sel := []hookGoldenMode{modes[0], modes[1], modes[5]}
	only := os.Getenv("DC_REVIEW2_ONLY")
	for _, h := range hookGoldenHooks() {
		event := h.events[0]
		for _, e := range review2Envs() {
			for _, m := range sel {
				for _, a := range []string{"allow", "block-output", "block-bare", "unreachable"} {
					add(hookGoldenCase{id: "/hostile-" + e.name, hook: h, mode: m, answer: byName[a], event: event, command: command, env: e.env})
				}
			}
		}
		for _, m := range sel {
			for _, a := range review2Answers() {
				add(hookGoldenCase{id: "/rv-answer", hook: h, mode: m, answer: a, event: event, command: command})
			}
			// stdin around the here-string threshold and the transport cap.
			for _, n := range []int{4093, 4094, 4095, 4096, 4097, 921599, 921600, 921601, 1048576, 1048577} {
				var p []byte
				lo, hi := 0, n
				for lo < hi {
					mid := (lo + hi) / 2
					if len(h.payload(event, strings.Repeat("a", mid), "/w")) < n {
						lo = mid + 1
					} else {
						hi = mid
					}
				}
				p = h.payload(event, strings.Repeat("a", lo), "/w")
				for _, a := range []string{"allow", "block-bare"} {
					add(hookGoldenCase{id: fmt.Sprintf("/rv-stdin-%d-got-%d", n, len(p)), hook: h, mode: m, answer: byName[a], event: event, stdin: p})
					add(hookGoldenCase{id: fmt.Sprintf("/rv-stdin-nl-%d-got-%d", n, len(p)+1), hook: h, mode: m, answer: byName[a], event: event, stdin: append(append([]byte(nil), p...), '\n')})
				}
			}
			for name, s := range map[string][]byte{
				"nul-first":     append([]byte{0}, h.payload(event, command, "/w")...),
				"nul-after-cap": append(h.payload(event, strings.Repeat("a", 1048600), "/w"), 0),
				"cr-only":       []byte("\r"),
				"newlines":      []byte("\n\n\n"),
				"invalid-utf8":  h.payload(event, "cat \xff\xfe", "/w"),
			} {
				for _, a := range []string{"allow", "block-bare"} {
					add(hookGoldenCase{id: "/rv-stdin-" + name, hook: h, mode: m, answer: byName[a], event: event, stdin: s})
				}
			}
		}
	}
	if only != "" {
		kept := cases[:0]
		for _, c := range cases {
			if strings.Contains(c.id, only) {
				kept = append(kept, c)
			}
		}
		cases = kept
	}
	return cases
}

// review2Env replaces <BASE> and takes DCREVIEW_STDIN_DELAY_MS out of a
// case's environment (runHookGoldenCase).
func review2Env(env []string, base string) ([]string, time.Duration) {
	out := env[:0:0]
	var delay time.Duration
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "DCREVIEW_STDIN_DELAY_MS="); ok {
			ms, _ := strconv.Atoi(v)
			delay = time.Duration(ms) * time.Millisecond
			continue
		}
		out = append(out, strings.ReplaceAll(kv, "<BASE>", base))
	}
	return out, delay
}

func TestShellHookHostileReview2(t *testing.T) {
	dump := os.Getenv("DC_REVIEW2_DUMP")
	if dump == "" {
		t.Skip("DC_REVIEW2_DUMP=DIR runs the review-2 cases and dumps each observation")
	}
	if err := os.MkdirAll(dump, 0o755); err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	installNativeGatewayForHookTest(t, filepath.Join(scratch, "probe-gw"))
	installNativeHookPostForHookTest(t, filepath.Join(scratch, "probe-post"))
	cases := review2Cases(t)
	base, err := os.MkdirTemp("/tmp", "dcr2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(filepath.Join(base, "exit0.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workers := 32
	if v, err := strconv.Atoi(os.Getenv("DC_HOOK_GOLDEN_WORKERS")); err == nil && v > 0 {
		workers = v
	}
	var (
		mu       sync.Mutex
		failures []string
		next     atomic.Int64
		wg       sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(cases) {
					return
				}
				c := cases[i]
				obs, err := runHookGoldenCase(base, i, c)
				if err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("%s: setup: %v", c.id, err))
					mu.Unlock()
					continue
				}
				body, _ := json.MarshalIndent(obs, "", "  ")
				_ = os.WriteFile(filepath.Join(dump, strings.ReplaceAll(c.id, "/", "_")+".json"), body, 0o644)
			}
		}()
	}
	wg.Wait()
	sort.Strings(failures)
	for _, f := range failures {
		t.Log(f)
	}
	t.Logf("%d review-2 cases, %d setup failures", len(cases), len(failures))
}

// TestSandboxHookScrubClassReview2 exports, one at a time, every name the
// rendered sandbox hook and its helpers assign or read and every bash
// special, then all of them together: the scrub unsets each exported name
// after _hardening.sh is sourced. A block and an ingress outage must still
// block. It logs, and does not fail on, every run that did not block.
func TestSandboxHookScrubClassReview2(t *testing.T) {
	if os.Getenv("DC_REVIEW2_SANDBOX") != "1" {
		t.Skip("DC_REVIEW2_SANDBOX=1 runs the review-2 sandbox scrub cases")
	}
	keep := map[string]bool{"DEFENSECLAW_SANDBOX_TOKEN": true, "CLAUDE_TOOL_NAME": true, "TOOL_NAME": true, "HOME": true, "PWD": true,
		"DEFENSECLAW_HOME": true, "DEFENSECLAW_MANAGED_HOOK": true, "PATH": true,
		"DEFENSECLAW_TRACEPARENT": true, "DEFENSECLAW_TRACESTATE": true, "OTEL_TRACEPARENT": true, "OTEL_TRACESTATE": true, "TRACEPARENT": true, "TRACESTATE": true}
	nameRE := regexp.MustCompile(`(?:\$\{?#?!?|\b)([A-Za-z_][A-Za-z0-9_]*)(?:=|\b)`)
	var bad atomic.Int64
	for _, tc := range sandboxHookCases() {
		tc := tc
		t.Run(tc.script+"-"+tc.connector, func(t *testing.T) {
			t.Parallel()
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			names := map[string]bool{}
			for _, n := range review2BashSpecials {
				names[n] = true
			}
			for _, n := range review2DCNames {
				names[n] = true
			}
			_ = filepath.Walk(h.root, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(p, ".sh") {
					return nil
				}
				b, _ := os.ReadFile(p)
				for _, m := range nameRE.FindAllStringSubmatch(string(b), -1) {
					n := m[1]
					if n == strings.ToUpper(n) || strings.HasPrefix(n, "_dc") || strings.HasPrefix(n, "_DC") {
						names[n] = true
					}
				}
				return nil
			})
			var list []string
			for n := range names {
				if !keep[n] {
					list = append(list, n)
				}
			}
			sort.Strings(list)
			replies := map[string][]string{
				"block": {`200|{"action":"block","reason":"nope"}`},
				"down":  {"exit:7", "exit:7"},
			}
			script := SandboxHookDir + "/" + tc.script
			try := func(label string, env map[string]string) {
				for rname, r := range replies {
					full := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash"}
					for k, v := range env {
						full[k] = v
					}
					run := h.run(t, script, tc.args, tc.stdin, full, r)
					if f := sandboxHookFailObject[tc.connector]; !tc.blocked(run) || tc.lifecycle && f != nil && !f(run) {
						bad.Add(1)
						t.Logf("SBXR-NOT-BLOCKED %s %s %s exit=%d stdout=%q stderr=%q", tc.script, label, rname, run.exitCode,
							run.stdout, review2Tail(run.stderr))
					}
				}
			}
			all := map[string]string{}
			for _, n := range list {
				try(n, map[string]string{n: "5"})
				all[n] = "5"
			}
			try("ALL", all)
			t.Logf("SBXR-DONE %s names=%d", tc.script, len(list))
		})
	}
	t.Cleanup(func() { t.Logf("SBXR-TOTAL-NOT-BLOCKED %d", bad.Load()) })
}

func review2Tail(s string) string {
	if len(s) > 300 {
		return s[len(s)-300:]
	}
	return s
}
