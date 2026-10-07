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

package tetragon

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// tree builds exec events with exec ids and parents, the way Tetragon
// reports them.
type tree struct {
	t      *testing.T
	mapper *Mapper
	procs  map[string]*pb.Process
	pid    uint32
}

func newTree(t *testing.T) *tree {
	return &tree{t: t, mapper: NewMapper(MapperConfig{Homes: []string{fixtureHome}}), procs: map[string]*pb.Process{}, pid: 5000}
}

// exec reports name's exec under parent ("" for a process whose parent the
// helper never saw) and returns what was forwarded.
func (tr *tree) exec(name, parent, binary, args string, uid uint32) []plane.Event {
	tr.pid++
	process := &pb.Process{
		ExecId: name, Pid: u32(tr.pid), Uid: u32(uid), Binary: binary, Arguments: args,
		ParentExecId: "unseen-" + name,
	}
	var parentProcess *pb.Process
	if parent != "" {
		parentProcess = tr.procs[parent]
		process.ParentExecId = parent
	}
	tr.procs[name] = process
	return tr.mapper.Map(execOf(process, parentProcess)).Events
}

func (tr *tree) exit(name string) []plane.Event {
	return tr.mapper.Map(exitOf(tr.procs[name])).Events
}

const (
	hookScript  = fixtureHome + "/.defenseclaw/hooks/claude-code-hook.sh"
	nativeHook  = "/opt/defenseclaw/bin/defenseclaw-hook"
	claudeBin   = fixtureHome + "/.local/bin/claude"
	toolShellCm = `-c "source ` + fixtureHome + `/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '%s' < /dev/null"`
)

func mustMark(t *testing.T, events []plane.Event, mark plane.HookMark, what string) {
	t.Helper()
	if len(events) != 1 || events[0].Hook != mark {
		t.Fatalf("%s: %+v, want one event marked %q", what, events, mark)
	}
}

func TestSelfFilterSummarizesARealScriptHook(t *testing.T) {
	tr := newTree(t)
	tr.exec("login", "", "/usr/bin/bash", "", 1001)
	tr.exec("claude", "login", claudeBin, "", 1001)
	mustMark(t, tr.exec("launcher", "claude", "/bin/sh", "-c "+hookScript, 1001), "", "the launcher")
	mustMark(t, tr.exec("hook", "launcher", hookScript, hookScript, 1001), plane.HookVerified, "the hook")
	for i, tool := range []string{"/usr/bin/jq", "/usr/bin/curl", "/usr/bin/find", "/usr/bin/mkdir"} {
		if events := tr.exec("tool"+strconv.Itoa(i), "hook", tool, "-x", 1001); len(events) != 0 {
			t.Fatalf("%s under a verified hook was forwarded: %+v", tool, events)
		}
	}
	// A tool's own child that is a tool is summarized too.
	if events := tr.exec("tool-child", "tool1", "/usr/bin/cat", "in.json", 1001); len(events) != 0 {
		t.Fatalf("a tool's tool child was forwarded: %+v", events)
	}
	// Anything else under the hook is forwarded, marked.
	mustMark(t, tr.exec("odd", "hook", "/usr/bin/bash", "-i", 1001), plane.HookUnexpected, "a shell under the hook")
	mustMark(t, tr.exec("odd-child", "odd", "/usr/bin/cat", "x", 1001), plane.HookUnexpected, "the shell's child")
	mustMark(t, tr.exec("planted", "hook", fixtureHome+"/bin/curl", "-x", 1001), plane.HookUnexpected, "a planted curl")
	exit := tr.exit("hook")
	if len(exit) != 1 || exit[0].Hook != plane.HookVerified || exit[0].HookTools != 5 {
		t.Fatalf("hook exit %+v", exit)
	}
}

func TestSelfFilterVerifiesTheNativeManagedHook(t *testing.T) {
	tr := newTree(t)
	tr.exec("claude", "", claudeBin, "", 1001)
	launcher := `-c "'` + nativeHook + `' hook --connector claudecode --enterprise-managed --event 'PreToolUse'"`
	tr.exec("launcher", "claude", "/bin/sh", launcher, 1001)
	hook := tr.exec("hook", "launcher", nativeHook, "hook --connector claudecode --enterprise-managed --event PreToolUse", 1001)
	mustMark(t, hook, plane.HookVerified, "the native hook")
	if hook[0].Cmdline != nativeHook+" hook --connector claudecode --enterprise-managed --event PreToolUse" {
		t.Fatalf("cmdline %q", hook[0].Cmdline)
	}
	// The native hook starts no processes, so every child is unexpected,
	// the tool names included.
	mustMark(t, tr.exec("curl", "hook", "/usr/bin/curl", "-x", 1001), plane.HookUnexpected, "a child of the native hook")
	// Run directly by the agent (no launcher) and with a contract version.
	tr.exec("codex", "", "/usr/local/bin/codex", "", 1001)
	mustMark(t, tr.exec("hook2", "codex", nativeHook, "hook --connector codex --enterprise-managed --hook-contract 2", 1001),
		plane.HookVerified, "a directly launched native hook")
}

func TestSelfFilterForwardsWrappersFromAToolShell(t *testing.T) {
	cases := []struct {
		name  string
		build func(tr *tree) []plane.Event
	}{
		{"bash -c wrapper inside a tool call", func(tr *tree) []plane.Event {
			tr.exec("tool", "claude", "/usr/bin/bash", fmt.Sprintf(toolShellCm, "bash -c "+hookScript), 1001)
			tr.exec("wrapper", "tool", "/usr/bin/bash", "-c "+hookScript, 1001)
			return tr.exec("hook", "wrapper", hookScript, hookScript, 1001)
		}},
		{"hook run straight from a tool call", func(tr *tree) []plane.Event {
			tr.exec("tool", "claude", "/usr/bin/bash", fmt.Sprintf(toolShellCm, hookScript), 1001)
			return tr.exec("hook", "tool", hookScript, hookScript, 1001)
		}},
		{"environment-variable wrapper", func(tr *tree) []plane.Event {
			tr.exec("wrapper", "claude", "/bin/sh", `-c "DEFENSECLAW_X=1 `+hookScript+`"`, 1001)
			return tr.exec("hook", "wrapper", hookScript, hookScript, 1001)
		}},
		{"env program wrapper", func(tr *tree) []plane.Event {
			tr.exec("wrapper", "claude", "/bin/sh", `-c "env DEFENSECLAW_X=1 `+hookScript+`"`, 1001)
			return tr.exec("hook", "wrapper", hookScript, hookScript, 1001)
		}},
		{"interpreter inside a tool call", func(tr *tree) []plane.Event {
			tr.exec("tool", "claude", "/usr/bin/bash", fmt.Sprintf(toolShellCm, "python3 run.py"), 1001)
			tr.exec("py", "tool", "/usr/bin/python3", "run.py", 1001)
			return tr.exec("hook", "py", nativeHook, "hook --connector claudecode --enterprise-managed", 1001)
		}},
		{"launcher with a second command", func(tr *tree) []plane.Event {
			tr.exec("wrapper", "claude", "/bin/sh", `-c "`+hookScript+`; cat /etc/hostname"`, 1001)
			return tr.exec("hook", "wrapper", hookScript, hookScript, 1001)
		}},
		{"another user's hook under this agent", func(tr *tree) []plane.Event {
			tr.exec("launcher", "claude", "/bin/sh", "-c "+hookScript, 1001)
			return tr.exec("hook", "launcher", hookScript, hookScript, 1002)
		}},
		{"a hook script outside the enrolled homes", func(tr *tree) []plane.Event {
			other := "/home/other/.defenseclaw/hooks/claude-code-hook.sh"
			tr.exec("launcher", "claude", "/bin/sh", "-c "+other, 1001)
			return tr.exec("hook", "launcher", other, other, 1001)
		}},
		{"native hook with extra arguments", func(tr *tree) []plane.Event {
			return tr.exec("hook", "claude", nativeHook, "hook --connector claudecode --enterprise-managed --gateway 127.0.0.1:1", 1001)
		}},
		{"hook whose agent the helper never saw", func(tr *tree) []plane.Event {
			tr.exec("launcher", "", "/bin/sh", "-c "+hookScript, 1001)
			return tr.exec("hook", "launcher", hookScript, hookScript, 1001)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTree(t)
			tr.exec("claude", "", claudeBin, "", 1001)
			mustMark(t, tc.build(tr), "", "the wrapped hook")
			// Its children are forwarded as ordinary processes, scored.
			if events := tr.exec("child", "hook", "/usr/bin/curl", "-x", 1001); len(events) != 1 || events[0].Hook != "" {
				t.Fatalf("child of an unverified hook: %+v", events)
			}
		})
	}
}

func TestLauncherCommandAndSimpleWords(t *testing.T) {
	for args, want := range map[string]string{
		"-c " + hookScript:            hookScript,
		`-c "'/opt/x' hook --a b"`:    `'/opt/x' hook --a b`,
		"-lc " + hookScript:           hookScript,
		"-l -c " + hookScript:         hookScript,
		"-c " + hookScript + " extra": "",
		hookScript:                    "",
		"-x -c " + hookScript:         "",
		`-c "unterminated`:            "",
	} {
		got, ok := launcherCommand(args)
		if (want == "") == ok || got != want {
			t.Fatalf("launcherCommand(%q) = %q %v, want %q", args, got, ok, want)
		}
	}
	for command, ok := range map[string]bool{
		`'/opt/x' hook --a 'b'`: true,
		`/opt/x "hook"`:         true,
		`FOO=1 /opt/x`:          false,
		`/opt/x; id`:            false,
		`/opt/x | tee`:          false,
		`/opt/x $(id)`:          false,
		"/opt/x `id`":           false,
		`/opt/x "$HOME"`:        false,
		`/opt/x > out`:          false,
		`/opt/x \ y`:            false,
	} {
		if _, got := simpleWords(command); got != ok {
			t.Fatalf("simpleWords(%q) ok=%v, want %v", command, got, ok)
		}
	}
}
