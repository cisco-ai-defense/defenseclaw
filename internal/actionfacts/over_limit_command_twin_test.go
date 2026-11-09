// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func overLimitCommandInput(t *testing.T, tool, command string) (Input, Facts) {
	t.Helper()
	input := Input{Tool: tool, Args: overLimitArgs(t, map[string]any{"cmd": command, "workdir": "/srv/app"})}
	return input, Analyze(input)
}

// TestOverLimitCommandBoundedTwin pins that a command over the string limit
// by white space padding has a twin that reads as the unpadded command: the
// protected redirect is a path fact of it. Text padding has none, nor does a
// structured write tool or a call within the limits.
func TestOverLimitCommandBoundedTwin(t *testing.T) {
	const attack = "echo /usr/local/lib/libreview.so > /etc/ld.so.preload"
	for _, c := range []struct{ name, command string }{
		{"trailing", attack + strings.Repeat(" ", 300000)},
		{"leading", strings.Repeat("\t", 300000) + attack},
		{"inner", "echo /usr/local/lib/libreview.so" + strings.Repeat(" ", 300000) + "> /etc/ld.so.preload"},
		{"line breaks", attack + strings.Repeat("\n \n", 100000)},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitCommandInput(t, "exec_command", c.command)
			if facts.Parse.Status != StatusLimitExceeded {
				t.Fatalf("not limit-exceeded: %s", facts.Parse.Status)
			}
			twin, ok := OverLimitCommandBoundedTwin(input, facts)
			if !ok {
				t.Fatal("no twin")
			}
			view := Analyze(twin)
			if view.Parse.Status == StatusLimitExceeded {
				t.Fatalf("twin still exceeds a limit: %s", view.Parse.Status)
			}
			found := false
			for _, path := range view.Paths {
				found = found || path.Normalized == "/etc/ld.so.preload"
			}
			if !found {
				t.Fatalf("the twin has no path fact for the protected redirect: %s", twin.Args)
			}
		})
	}
	opaque := attack + " # " + strings.Repeat("x", 300000)
	input, facts := overLimitCommandInput(t, "exec_command", opaque)
	if _, ok := OverLimitCommandBoundedTwin(input, facts); ok {
		t.Fatal("text that is not white space padding has a twin")
	}
	input, facts = overLimitCommandInput(t, "exec_command", "echo ok")
	if _, ok := OverLimitCommandBoundedTwin(input, facts); ok {
		t.Fatal("a call within the limits has a twin")
	}
	patch := Input{Tool: "apply_patch", Args: overLimitArgs(t, map[string]any{"command": "*** Begin Patch\n*** Add File: /srv/a\n+" + strings.Repeat(" ", 300000) + "\n*** End Patch\n"})}
	if _, ok := OverLimitCommandBoundedTwin(patch, Analyze(patch)); ok {
		t.Fatal("a structured write tool has a command twin")
	}
}

// TestBoundedCommandText pins the bounded form: only a run of white space
// longer than maxKeptWhiteSpaceRun changes, and it keeps a line break.
func TestBoundedCommandText(t *testing.T) {
	short := strings.Repeat(" ", maxKeptWhiteSpaceRun)
	for _, c := range []struct {
		name, text, want string
		ok               bool
	}{
		{"short runs stay", "a" + short + "b" + strings.Repeat("c", maxCommandBytes), "", false},
		{"long run is one space", "a" + strings.Repeat(" ", maxCommandBytes) + "b", "a b", true},
		{"long run with a break is one break", "a" + strings.Repeat(" \n", maxCommandBytes) + "b", "a\nb", true},
		{"short run kept beside a long one", "a" + short + "b" + strings.Repeat("\t", maxCommandBytes) + "c", "a" + short + "b c", true},
		{"all white space", strings.Repeat(" ", maxCommandBytes+1), "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := boundedCommandText(c.text)
			if ok != c.ok || (ok && got != c.want) {
				t.Fatalf("got %q ok=%t, want %q ok=%t", got, ok, c.want, c.ok)
			}
		})
	}
}

// TestOverLimitWriteElidedContentTargetRelativeLink pins that the client's
// attested target of a relative operand is read under the key the client
// gives it, the operand placed in the working directory.
func TestOverLimitWriteElidedContentTargetRelativeLink(t *testing.T) {
	opaque := "*** Begin Patch\n*** Add File: lnk-preload\n+" + strings.Repeat("x", 300000) + "\n*** End Patch\n"
	raw, err := json.Marshal(map[string]any{"command": opaque, "workdir": "/srv/app"})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: "apply_patch", Args: raw, CWD: "/srv/app"}
	facts := Analyze(input)
	for _, c := range []struct {
		name     string
		resolved map[string]string
		class    string
	}{
		{"placed key", map[string]string{"/srv/app/lnk-preload": "/etc/ld.so.preload"}, "global-preload"},
		{"ordinary link", map[string]string{"/srv/app/lnk-preload": "/srv/app/notes.txt"}, ""},
		{"no evidence", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			class, ok := OverLimitWriteElidedContentTarget(input, facts, c.resolved)
			if class != c.class || ok != (c.class != "") {
				t.Fatalf("class=%q ok=%t, want %q", class, ok, c.class)
			}
		})
	}
}
