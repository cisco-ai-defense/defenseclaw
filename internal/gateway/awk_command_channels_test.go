// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-0499: awk starts a shell command through system(),
// print | and | getline. A command written as string literals is judged as the
// hook running it directly, in the four cells (both connectors, per-user and
// managed) of every pack; one built at run time is the unknown tier of the
// pack, never an allow; a program with no command channel is judged as before.
// The rows are the commands of the managed hook fixture (the keys file, a link
// to it, an ordinary file) put through the three channels by a text
// transformation; none is typed as an attack string.

// awkChannelWrap writes command as the command each awk channel starts.
func awkChannelWrap(channel, command string) string {
	literal := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(command)
	var program string
	switch channel {
	case "system":
		program = `BEGIN{system("` + literal + `")}`
	case "print-pipe":
		program = `BEGIN{print "" | "` + literal + `"}`
	case "getline":
		program = `BEGIN{"` + literal + `" | getline x}`
	}
	return "awk '" + strings.ReplaceAll(program, "'", `'\''`) + "'"
}

var awkChannels = []string{"system", "print-pipe", "getline"}

func awkPackFixture(t *testing.T, pack string) b36ManagedHookFixture {
	t.Helper()
	f := newB36ManagedHookFixture(t)
	switch pack {
	case "strict":
		f = f.strict(t)
	case "permissive":
		f.packDir = filepath.Join(guardrailPoliciesRoot(t), "permissive")
	}
	if err := os.WriteFile(filepath.Join(f.project, "ordinary", "a.txt"), []byte("a b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// awkVerdicts answers each command in the four cells and returns the calls
// grouped by command.
func awkVerdicts(t *testing.T, f b36ManagedHookFixture, commands []string) map[string][]*hookCall {
	t.Helper()
	payloads := make([][]byte, len(commands))
	for i, command := range commands {
		payloads[i] = f.payload(t, command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, command := range commands {
		calls = append(calls, everyMode(command, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	byCommand := map[string][]*hookCall{}
	for i, call := range calls {
		byCommand[commands[i/4]] = append(byCommand[commands[i/4]], call)
	}
	return byCommand
}

func TestAwkCommandChannelsAreJudgedAsTheDirectCommand(t *testing.T) {
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			protected := []string{
				"touch " + f.keys,
				"cd ordinary && touch " + f.keys,
				"touch keylink",
			}
			ordinary := []string{
				"touch ordinary/new.txt",
				"sort -u ordinary/a.txt",
				"wc -l ordinary/a.txt",
			}
			var commands []string
			for _, direct := range append(slices.Clone(protected), ordinary...) {
				commands = append(commands, direct)
				for _, channel := range awkChannels {
					commands = append(commands, awkChannelWrap(channel, direct))
				}
			}
			got := awkVerdicts(t, f, commands)
			for _, direct := range append(slices.Clone(protected), ordinary...) {
				want := "allow"
				if slices.Contains(protected, direct) {
					want = "block"
				}
				for _, call := range got[direct] {
					if call.verdict != want {
						t.Errorf("direct %s: %s, want %s", call.name, call.verdict, want)
					}
				}
				for _, channel := range awkChannels {
					for _, call := range got[awkChannelWrap(channel, direct)] {
						if call.verdict != want {
							t.Errorf("%s of %q: %s, want %s (the direct command's)", channel, direct, call.verdict, want)
						}
					}
				}
			}
		})
	}
}

func TestAwkProgramWithNoCommandChannelIsUnchanged(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			commands := []string{
				`awk '{print $1, $2}' ordinary/a.txt`,
				`awk '{print $1 | "sort"}' ordinary/a.txt`,
				`awk '{print $1 | "wc -l"}' ordinary/a.txt`,
				`awk 'BEGIN{system("wc -l ordinary/a.txt")}'`,
				`awk '/a|b/ {print "x|y"}' ordinary/a.txt`,
				`awk '{print $1 > "ordinary/out.txt"}' ordinary/a.txt`,
			}
			for command, calls := range awkVerdicts(t, f, commands) {
				for _, call := range calls {
					if call.verdict != "allow" || strings.Contains(call.body, awkprog.DynamicReason) {
						t.Errorf("%s: %s %s, want an allow with no awk finding", command, call.name, call.verdict)
					}
				}
			}
		})
	}
}

// A command built from a field or a variable has no text to judge: the
// default and permissive packs alert, the strict pack blocks, in every cell.
func TestAwkCommandBuiltAtRunTimeIsTheUnknownTier(t *testing.T) {
	commands := []string{
		`awk '{system($1)}' ordinary/a.txt`,
		`awk '{print $1 | cmd}' ordinary/a.txt`,
		`awk 'BEGIN{cmd | getline x}'`,
		`awk '{system("wc -l " $1)}' ordinary/a.txt`,
	}
	for pack, want := range map[string]string{"default": "alert", "permissive": "alert", "strict": "block"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			for command, calls := range awkVerdicts(t, f, commands) {
				for _, call := range calls {
					if call.verdict != want || !strings.Contains(call.body, awkprog.DynamicReason) {
						t.Errorf("%s: %s %s, want %s naming %s", command, call.name, call.verdict, want, awkprog.DynamicReason)
					}
				}
			}
		})
	}
}

// The depth cap of the awk reading is a lane of the bound rule: an awk program
// in shell STRINGs nested past maxNestedShellStrings is truncated and named
// "depth", at the cap it is read in full.
func init() {
	registerBoundedLane(boundedLaneCap{lane: "awk command in nested shell strings", cap: bounded.Depth,
		limit: actionfacts.MaxAwkNestedShellStrings,
		gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.nested || shape.multi {
				return boundedLaneCall{}, false
			}
			command := awkChannelWrap("system", "true")
			for range size {
				command = "bash -c '" + strings.ReplaceAll(command, "'", `'\''`) + "'"
			}
			if shape.seen {
				command = boundedShellSeen + "; " + command
			}
			if shape.seenAfter {
				command += "; " + boundedShellSeen
			}
			return boundedShellCommand(command), true
		},
		seen: boundedShellSeenCall})
}
