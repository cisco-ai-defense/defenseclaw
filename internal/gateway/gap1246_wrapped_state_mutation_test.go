// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// gap1246Fixture is a home with the DefenseClaw state and a project folder,
// and a verdict reader for the OpenClaw inspect route and the Claude Code
// hook route of each of the five tiers.
func gap1246Fixture(t *testing.T) (cwd string, routes []gap1246Route) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	calls := 0
	for _, p := range gap0437Packs {
		inspect := gap0437Server(t, p, "openclaw", "action")
		inspect.inspectToolScanTimeout = 30 * time.Second
		hook := gap0437Server(t, p, "claudecode", "action")
		routes = append(routes,
			gap1246Route{name: "inspect/" + p.name, verdict: func(command string) string {
				action, _ := gap0437Inspect(t, inspect, cwd, command)["action"].(string)
				return action
			}},
			gap1246Route{name: "cchook/" + p.name, verdict: func(command string) string {
				calls++
				return gap1246HookAction(gap0437Hook(t, hook, cwd, "gap1246-"+strconv.Itoa(calls), command))
			}},
		)
	}
	return cwd, routes
}

type gap1246Route struct {
	name    string
	verdict func(command string) string
}

// gap1246HookAction is the decision of a Claude Code hook reply.
func gap1246HookAction(out map[string]any) string {
	if action, _ := out["action"].(string); action != "" {
		return action
	}
	if specific, ok := out["hookSpecificOutput"].(map[string]any); ok {
		if decision, _ := specific["permissionDecision"].(string); decision != "" {
			return decision
		}
	}
	if decision, _ := out["decision"].(string); decision != "" {
		return decision
	}
	return "allow"
}

// gap1246Blocks reports a hook or inspect verdict that stops the call.
func gap1246Blocks(action string) bool { return action == "block" || action == "deny" }

// TestStateMutationBehindAnyPrefixWrapperFiveTiers: any program run through a
// static prefix wrapper changes what the plain call changes, so a plain
// find -delete, find -exec rm, truncate or git clean of the DefenseClaw state
// that blocks blocks behind setsid, stdbuf, ionice, doas, taskset, chrt and
// flock too, as it did behind nohup, sudo, timeout, env, command and exec.
// They were a clean allow in all five tiers on the inspect and hook routes
// (rel-1-0-10:GAP-1246: the wrapper reader stopped only at a list of
// writers, deletes and shells). A program word with no static spelling
// ("$(echo nice)") may name a wrapper, so the call after it is read too. The
// plain call is the oracle, never a hard-coded letter; the same wrappers
// around a mutation in the project stay allowed.
func TestStateMutationBehindAnyPrefixWrapperFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text; OpenClaw exec is PowerShell on native Windows")
	}
	_, routes := gap1246Fixture(t)
	state := "~/.defenseclaw"
	mutations := []string{
		"find " + state + " -delete",
		"find " + state + " -type f -exec rm {} +",
		"truncate -s0 " + state + "/config.yaml",
		"git clean -fdx " + state,
		"find ~ -delete",
	}
	wrappers := []string{
		"nice", "nice -n 5", "setsid", "stdbuf -o0", "ionice -c3", "ionice -c 3", "doas",
		"taskset -c 0", "chrt -i 0", "flock .l", "time", "nohup", "sudo -n", "\"$(echo nice)\"",
	}
	benign := []string{
		"nice find . -name '*.pyc' -delete", "nice find ./build -delete", "setsid truncate -s0 out.log",
		"\"$X\" ls -la", "\"$(echo nice)\" rm -rf ./build",
	}
	required := map[string]bool{mutations[0]: true, mutations[2]: true}
	for _, route := range routes {
		for _, plain := range mutations {
			oracle := route.verdict(plain)
			if !gap1246Blocks(oracle) {
				if required[plain] {
					t.Fatalf("%s: %q is %s, the oracle needs a block", route.name, plain, oracle)
				}
				continue
			}
			for _, wrapper := range wrappers {
				if got := route.verdict(wrapper + " " + plain); got != oracle {
					t.Errorf("%s: %q is %s, its plain call is %s", route.name, wrapper+" "+plain, got, oracle)
				}
			}
		}
		if oracle, got := route.verdict("rm -rf "+state), route.verdict("\"$(echo nice)\" rm -rf "+state); got != oracle {
			t.Errorf("%s: \"$(echo nice)\" rm -rf %s is %s, its plain call is %s", route.name, state, got, oracle)
		}
		for _, command := range benign {
			if got := route.verdict(command); gap1246Blocks(got) {
				t.Errorf("%s: %q is %s, want no block", route.name, command, got)
			}
		}
	}
}

// TestXargsStdinReaderReadsTheShellWordsFiveTiers: xargs runs its program with
// the words the stage before it prints. A "~" that stage got from the source
// quoted or escaped is a literal ~ (a folder ./~), not the home, so such a
// delete gets the verdict of rm -rf ./~; s7/shellres had read it as the home
// and blocked it in all five tiers where rel allowed it. xargs -I, echo -n
// with -0, printf with the home as the format, and a wrapper xargs runs
// before rm remove the home like rm -rf ~ (rel-1-0-10:GAP-1247). The plain
// call is the oracle.
func TestXargsStdinReaderReadsTheShellWordsFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text; OpenClaw exec is PowerShell on native Windows")
	}
	_, routes := gap1246Fixture(t)
	cases := map[string][]string{
		"rm -rf ./~": {
			"echo '~' | xargs rm -rf", "echo \\~ | xargs rm -rf", "echo \"~\" | xargs rm -rf",
			"printf '%s\\n' \"~\" | xargs rm -rf", "echo '~' | xargs -I{} rm -rf {}",
		},
		"rm -rf ~": {
			"echo ~ | xargs -I{} rm -rf {}", "echo -n ~ | xargs -0 rm -rf", "printf ~ | xargs rm -rf",
			"echo ~ | xargs sudo rm -rf", "echo ~ | xargs nice rm -rf", "echo ~ | xargs rm -rf",
		},
	}
	for _, route := range routes {
		if !gap1246Blocks(route.verdict("rm -rf ~")) {
			t.Fatalf("%s: rm -rf ~ is %s, the oracle needs a block", route.name, route.verdict("rm -rf ~"))
		}
		for plain, commands := range cases {
			oracle := route.verdict(plain)
			for _, command := range commands {
				if got := route.verdict(command); got != oracle {
					t.Errorf("%s: %q is %s, %q is %s", route.name, command, got, plain, oracle)
				}
			}
		}
	}
}
