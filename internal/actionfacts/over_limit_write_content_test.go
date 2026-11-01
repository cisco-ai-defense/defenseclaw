// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func overLimitContentInput(t *testing.T, tool string, args map[string]any) (Input, Facts) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: tool, Args: raw}
	return input, Analyze(input)
}

// TestOverLimitWriteBoundedTwin pins GAP-0687: a write whose text is over
// the string limit only by white space has a twin within the limits that
// carries the text as the file gets it; text with no bounded form has none.
func TestOverLimitWriteBoundedTwin(t *testing.T) {
	doc := `{"log-level":"warn"}`
	for _, c := range []struct {
		name, content, want string
		ok                  bool
	}{
		{"trailing spaces", doc + strings.Repeat(" ", 70000), doc, true},
		{"leading newlines", strings.Repeat("\n", 70000) + doc, doc, true},
		{"inner JSON white space", "{" + strings.Repeat(" ", 70000) + doc[1:], doc, true},
		{"opaque text", doc + "\n" + strings.Repeat("x", 70000), "", false},
		{"white space only", strings.Repeat(" ", 70000), "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitContentInput(t, "Write", map[string]any{"file_path": "/srv/app/config.json", "content": c.content})
			args, ok := OverLimitWriteBoundedTwin(input, facts)
			if ok != c.ok {
				t.Fatalf("ok = %t, want %t", ok, c.ok)
			}
			if !ok {
				return
			}
			var object map[string]string
			if err := json.Unmarshal(args, &object); err != nil || object["content"] != c.want || object["file_path"] != "/srv/app/config.json" {
				t.Fatalf("twin %s, want content %q", args, c.want)
			}
			if twin := Analyze(Input{Tool: "Write", Args: args}); !twin.Authoritative() {
				t.Fatalf("twin analysis %s %v", twin.Parse.Status, twin.Parse.Issues)
			}
		})
	}
	small, facts := overLimitContentInput(t, "Write", map[string]any{"file_path": "/srv/app/config.json", "content": doc})
	if _, ok := OverLimitWriteBoundedTwin(small, facts); ok {
		t.Fatal("a call within the limits has no twin")
	}
}

// TestOverLimitWriteElidedContentTarget pins which over-limit writes take
// the conservative content finding: only text with no bounded form written
// to a file a content rule decides on. Ordinary files never do.
func TestOverLimitWriteElidedContentTarget(t *testing.T) {
	opaque := "# a\n" + strings.Repeat("x", 70000)
	for _, c := range []struct {
		tool, key, target, content, class string
	}{
		{"Write", "file_path", "/etc/docker/daemon.json", opaque, "docker-daemon-config"},
		{"Write", "file_path", "/etc/sudoers.d/team", opaque, "sudoers"},
		{"write_file", "path", "/etc/passwd", opaque, "account-database"},
		{"Write", "file_path", "/etc/ld.so.preload", opaque, "global-preload"},
		{"Write", "file_path", "/etc/pam.d/sshd", opaque, "pam"},
		{"Write", "file_path", "/etc/docker/daemon.json", "{}" + strings.Repeat(" ", 70000), ""},
		{"Write", "file_path", "/srv/app/daemon.json", opaque, ""},
		{"Write", "file_path", "/srv/app/notes.md", opaque, ""},
	} {
		t.Run(c.target+"/"+c.class, func(t *testing.T) {
			input, facts := overLimitContentInput(t, c.tool, map[string]any{c.key: c.target, "content": c.content})
			class, ok := OverLimitWriteElidedContentTarget(input, facts)
			if class != c.class || ok != (c.class != "") {
				t.Fatalf("class = %q %t, want %q", class, ok, c.class)
			}
		})
	}
}
