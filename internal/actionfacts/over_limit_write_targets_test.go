// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// overLimitText is write content over maxArgsJSONBytes.
var overLimitText = strings.Repeat("# k\n", 70000)

func overLimitArgs(t *testing.T, fields map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustOverLimitJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func overLimitPatch(path string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n # base\n" +
		strings.Repeat("+# k\n", 70000) + "*** End Patch\n"
}

// A structured write tool call whose arguments are limit-exceeded still
// names its write target through the reduction, so the file-write rules can
// judge it (GAP-0674).
func TestOverLimitWriteTargetReductionNamesTheTarget(t *testing.T) {
	const keys = "/home/u/.ssh/authorized_keys"
	for _, row := range []struct {
		name, tool, cwd, want string
		fields                map[string]any
	}{
		{"claude write", "Write", "/home/u/proj", keys, map[string]any{"file_path": keys, "content": overLimitText}},
		{"claude write 100 KiB", "Write", "/home/u/proj", keys, map[string]any{"file_path": keys, "content": overLimitText[:100<<10]}},
		{"claude edit", "Edit", "/home/u/proj", keys, map[string]any{"file_path": keys, "old_string": "# base", "new_string": overLimitText}},
		{"claude multiedit", "MultiEdit", "/home/u/proj", keys, map[string]any{"file_path": keys,
			"edits": []any{map[string]any{"old_string": overLimitText, "new_string": overLimitText}}}},
		{"opencode write", "write", "/home/u/proj", keys, map[string]any{"filePath": keys, "content": overLimitText}},
		{"opencode edit", "edit", "/home/u/proj", keys, map[string]any{"filePath": keys, "oldString": "# base", "newString": overLimitText}},
		{"copilot create", "create", "/home/u/proj", keys, map[string]any{"path": keys, "file_text": overLimitText}},
		{"hermes write_file", "write_file", "/home/u/proj", keys, map[string]any{"path": keys, "content": overLimitText}},
		{"apply_patch", "apply_patch", "/home/u", ".ssh/authorized_keys", map[string]any{"command": overLimitPatch(".ssh/authorized_keys")}},
		{"apply_patch patchText", "apply_patch", "/home/u", ".ssh/authorized_keys", map[string]any{"patchText": overLimitPatch(".ssh/authorized_keys")}},
		// An absolute target is read as one (rel-1-0-6:GAP-0361).
		{"apply_patch absolute", "apply_patch", "/home/u/proj", keys, map[string]any{"command": overLimitPatch(keys)}},
		{"benign write", "Write", "/home/u/proj", "/home/u/proj/big.json", map[string]any{"file_path": "/home/u/proj/big.json", "content": overLimitText}},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: row.tool, Args: overLimitArgs(t, row.fields), CWD: row.cwd, ActiveHome: "/home/u"}
			facts := Analyze(input)
			if facts.Parse.Status != StatusLimitExceeded || !LimitExceededWriteTool(input, facts) {
				t.Fatalf("facts = %s, want a limit-exceeded write tool", facts.Parse.Status)
			}
			view, reduced, ok := OverLimitWriteTargetReduction(input, facts)
			if !ok {
				t.Fatal("no reduction")
			}
			if len(reduced) > 4<<10 {
				t.Fatalf("reduced args are %d bytes", len(reduced))
			}
			if !view.Authoritative() || view.Tool != row.tool {
				t.Fatalf("view = %s tool %q", view.Parse.Status, view.Tool)
			}
			found := false
			for _, path := range view.Paths {
				if path.Value == row.want && (path.Access == PathAccessWrite || path.Access == PathAccessAppend) {
					found = true
				}
			}
			if !found {
				t.Fatalf("view paths = %+v, want a write of %s", view.Paths, row.want)
			}
		})
	}
}

// A write tool call whose targets the reduction cannot read has none: the
// caller takes the conservative result. A non-write tool call over the limit
// is not a write tool call and keeps its limit-exceeded analysis.
func TestOverLimitWriteTargetReductionRefuses(t *testing.T) {
	const keys = "/home/u/.ssh/authorized_keys"
	truncated := overLimitArgs(t, map[string]any{"file_path": keys, "content": overLimitText})
	truncated = truncated[:len(truncated)-10]
	for _, row := range []struct {
		name, tool string
		args       json.RawMessage
		write      bool
	}{
		{"unknown key", "Write", overLimitArgs(t, map[string]any{"file_path": keys, "content": overLimitText, "mode": "x"}), true},
		{"large unknown key", "Write", overLimitArgs(t, map[string]any{"file_path": keys, "notes": overLimitText}), true},
		{"large target", "Write", overLimitArgs(t, map[string]any{"file_path": "/home/u/" + strings.Repeat("a", 5<<10), "content": overLimitText}), true},
		{"truncated", "Write", truncated, true},
		{"duplicate key", "Write", json.RawMessage(`{"file_path":"/tmp/a","file_path":"` + keys + `","content":"` + strings.Repeat("k", 300<<10) + `"}`), true},
		{"top-level string", "apply_patch", mustOverLimitJSON(t, overLimitPatch("a.txt")), true},
		{"patch without envelope", "apply_patch", overLimitArgs(t, map[string]any{"command": overLimitText}), true},
		{"over the scan ceiling", "Write", overLimitArgs(t, map[string]any{"file_path": keys, "content": strings.Repeat("k", maxOverLimitWriteArgsBytes)}), true},
		{"read tool", "Read", overLimitArgs(t, map[string]any{"file_path": keys, "pages": overLimitText}), false},
		{"grep tool", "Grep", overLimitArgs(t, map[string]any{"pattern": overLimitText}), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: row.tool, Args: row.args, CWD: "/home/u/proj", ActiveHome: "/home/u"}
			facts := Analyze(input)
			if got := LimitExceededWriteTool(input, facts); got != row.write {
				t.Fatalf("limit-exceeded write tool = %t, want %t (%s)", got, row.write, facts.Parse.Status)
			}
			if _, _, ok := OverLimitWriteTargetReduction(input, facts); ok {
				t.Fatal("reduced")
			}
		})
	}
}

// A call under the limits is not reduced: its own analysis judges it.
func TestOverLimitWriteTargetReductionLeavesCallsUnderTheLimit(t *testing.T) {
	input := Input{Tool: "Write", Args: overLimitArgs(t, map[string]any{"file_path": "/home/u/.ssh/authorized_keys", "content": "# k\n"}),
		CWD: "/home/u/proj", ActiveHome: "/home/u"}
	facts := Analyze(input)
	if !facts.Authoritative() || LimitExceededWriteTool(input, facts) {
		t.Fatalf("facts = %s", facts.Parse.Status)
	}
	if _, _, ok := OverLimitWriteTargetReduction(input, facts); ok {
		t.Fatal("reduced a call under the limit")
	}
}

// The compact envelope parses to the same changes as the full one.
func TestCompactPatchEnvelopeKeepsTheChanges(t *testing.T) {
	for _, envelope := range []string{
		"*** Begin Patch\n*** Add File: a.txt\n+x\n+y\n*** Update File: b.txt\n@@ one\n x\n-y\n-z\n+w\n@@ two\n+v\n*** Delete File: c.txt\n*** End Patch",
		"*** Begin Patch\r\n*** Update File: b.txt\r\n*** Move to: d.txt\r\n@@\r\n x\r\n+y\r\n*** End of File\r\n*** End Patch\r\n",
		"*** Begin Patch\n*** Update File: b.txt\n*** End Patch",
		"*** Begin Patch\n*** Add File: a.txt\n\n+x\n*** End Patch",
	} {
		budget := maxBoundedPatchBytes
		compact, _, _, ok := reducePatchEnvelope(envelope, false, &budget)
		if !ok {
			t.Fatalf("compact %q", envelope)
		}
		full, reduced := parsePatchEnvelope(envelope), parsePatchEnvelope(compact)
		if full.status != reduced.status || full.issue != reduced.issue || full.hasMove != reduced.hasMove ||
			len(full.changes) != len(reduced.changes) {
			t.Fatalf("%q: full %+v, compact %q %+v", envelope, full, compact, reduced)
		}
		for i := range full.changes {
			if full.changes[i] != reduced.changes[i] {
				t.Fatalf("%q: change %d %+v != %+v", envelope, i, full.changes[i], reduced.changes[i])
			}
		}
	}
}

func overLimitPatchInput(t *testing.T, patch string) (Input, Facts) {
	t.Helper()
	return overLimitContentInput(t, "apply_patch", map[string]any{"command": patch})
}

// TestOverLimitPatchBoundedTwin pins that a patch envelope over the argument
// limit only by white space has a twin within the limits that carries every
// file's text without the padding, so the content proofs read it; a patch
// with a file whose text has no bounded form has a twin that keeps that
// text out, and names the file.
func TestOverLimitPatchBoundedTwin(t *testing.T) {
	line := "/usr/local/lib/liblogger.so"
	for _, c := range []struct{ name, text string }{
		{"trailing", line + strings.Repeat(" ", 300000)},
		{"leading", strings.Repeat(" ", 300000) + line},
		{"inner", line + strings.Repeat("\t", 300000) + "/usr/local/lib/b.so"},
		{"padding lines", line + "\n+" + strings.Repeat("\n+  ", 100000)},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitPatchInput(t, "*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+"+c.text+"\n*** End Patch\n")
			if !LimitExceededWriteTool(input, facts) {
				t.Fatalf("not limit-exceeded: %s", facts.Parse.Status)
			}
			args, ok := OverLimitWriteBoundedTwin(input, facts)
			if !ok || len(args) > maxCommandBytes {
				t.Fatalf("twin ok=%t len=%d", ok, len(args))
			}
			twin := Input{Tool: "apply_patch", Args: args}
			if !ExactGlobalLDPreloadFileWrite(twin, Analyze(twin)) {
				t.Fatalf("content proof does not read the twin: %s", args)
			}
			if class, elided := OverLimitWriteElidedContentTarget(input, facts, nil); elided {
				t.Fatalf("padding left text out for %s", class)
			}
		})
	}
}

// TestOverLimitPatchElidedContentTargetIsPerFile pins that only the patch
// file whose own text could not be bounded has an unproven content rule.
func TestOverLimitPatchElidedContentTargetIsPerFile(t *testing.T) {
	opaque := strings.Repeat("x", 300000)
	for _, c := range []struct{ name, patch, class string }{
		{"opaque preload", "*** Add File: /etc/ld.so.preload\n+" + opaque + "\n", "global-preload"},
		{"opaque pam", "*** Add File: /etc/pam.d/sshd\n+" + opaque + "\n", "pam"},
		{"opaque update of daemon.json", "*** Update File: /etc/docker/daemon.json\n@@\n+" + opaque + "\n", "docker-daemon-config"},
		{"opaque ordinary file", "*** Add File: /srv/app/a.txt\n+" + opaque + "\n", ""},
		{"opaque ordinary beside small preload", "*** Add File: /srv/app/a.txt\n+" + opaque + "\n*** Add File: /etc/ld.so.preload\n+# none\n", ""},
		{"opaque preload beside small ordinary", "*** Add File: /srv/app/a.txt\n+ok\n*** Add File: /etc/ld.so.preload\n+" + opaque + "\n", "global-preload"},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitPatchInput(t, "*** Begin Patch\n"+c.patch+"*** End Patch\n")
			if !LimitExceededWriteTool(input, facts) {
				t.Fatalf("not limit-exceeded: %s", facts.Parse.Status)
			}
			class, ok := OverLimitWriteElidedContentTarget(input, facts, nil)
			if class != c.class || ok != (c.class != "") {
				t.Fatalf("class=%q ok=%t, want %q", class, ok, c.class)
			}
		})
	}
}

// TestOverLimitPatchEnvelopeBounded pins the reduction of a patch envelope
// itself: padding is removed from hunk lines, a run of white space inside a
// line is one space, ordinary indentation stays, and the paths and
// accesses of the envelope are those of the original.
func TestOverLimitPatchEnvelopeBounded(t *testing.T) {
	envelope := "*** Begin Patch\n*** Update File: b.txt\n*** Move to: d.txt\n@@ f   \n    indented  \n-old" +
		strings.Repeat(" ", 200) + "\n+a" + strings.Repeat(" ", 200) + "b\n+" + strings.Repeat(" ", 200) + "\n+" +
		strings.Repeat(" ", 200) + "\n*** End of File\n*** End Patch\n"
	budget := maxBoundedPatchBytes
	reduced, elided, unscoped, ok := reducePatchEnvelope(envelope, true, &budget)
	want := "*** Begin Patch\n*** Update File: b.txt\n*** Move to: d.txt\n@@ f\n    indented\n-old\n+a b\n+\n*** End of File\n*** End Patch\n"
	if !ok || reduced != want || len(elided) != 0 || unscoped {
		t.Fatalf("ok=%t elided=%v unscoped=%t reduced %q", ok, elided, unscoped, reduced)
	}
	full, got := parsePatchEnvelope(envelope), parsePatchEnvelope(reduced)
	if full.status != got.status || len(full.changes) != len(got.changes) || full.hasMove != got.hasMove {
		t.Fatalf("full %+v, reduced %+v", full, got)
	}
}
