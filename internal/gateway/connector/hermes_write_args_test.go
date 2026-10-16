// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestHermesTrustedWriteViews pins the projection of Hermes' native write
// tools onto one reviewed single-target write per file they change
// (GAP-0667).
func TestHermesTrustedWriteViews(t *testing.T) {
	unverified := []string{`apply_patch {}`}
	for _, test := range []struct {
		name, tool, args string
		want             []string
		wantOK           bool
	}{
		{name: "replace default mode", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y"}`,
			want: []string{`edit {"file_path":"a.txt","new_string":"y","old_string":"x"}`}, wantOK: true},
		{name: "replace mode, ignored keys", tool: "patch",
			args:   `{"mode":"replace","path":"a.txt","old_string":"x","new_string":"y","replace_all":true,"cross_profile":true,"patch":"*** Update File: b.txt","note":1}`,
			want:   []string{`edit {"file_path":"a.txt","new_string":"y","old_string":"x","replace_all":true}`},
			wantOK: true},
		{name: "replace all null", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y","replace_all":null}`,
			want: []string{`edit {"file_path":"a.txt","new_string":"y","old_string":"x"}`}, wantOK: true},
		{name: "v4a", tool: "patch", args: `{"mode":"patch","patch":"*** Begin Patch\n*** Update File: a.txt\n@@\n x\n+y\n*** Delete File: /abs/b.txt\n*** End Patch"}`,
			want: []string{`write_file {"content":"x","path":"a.txt"}`, `delete_file {"path":"/abs/b.txt"}`}, wantOK: true},
		{name: "v4a move", tool: "patch", args: `{"mode":"patch","patch":"*** Move File: a.md -> ~/b.md\n"}`,
			want: []string{`delete_file {"path":"a.md"}`, `write_file {"content":"x","path":"~/b.md"}`}, wantOK: true},
		// path is only checked and locked in this mode, never written.
		{name: "v4a with path", tool: "patch", args: `{"mode":"patch","path":"c.txt","patch":"*** Add File: a.txt\n+y"}`,
			want: []string{`write_file {"content":"y","path":"a.txt"}`}, wantOK: true},
		// An Add writes the "+" line contents of all its hunks joined with
		// "\n" (Hermes' _apply_add); other lines and a "\r" end are kept as
		// Hermes' parser keeps them.
		{name: "v4a add content", tool: "patch",
			args:   `{"mode":"patch","patch":"*** Begin Patch\n*** Add File: /etc/profile.d/x.sh\n+# loader\n ctx\n@@ h @@\n+export LD_PRELOAD=/l.so\r\n+\n*** Update File: b.txt\n x\n+y\n*** End Patch"}`,
			want:   []string{`write_file {"content":"# loader\nexport LD_PRELOAD=/l.so\r\n","path":"/etc/profile.d/x.sh"}`, `write_file {"content":"x","path":"b.txt"}`},
			wantOK: true},
		{name: "v4a add with no lines", tool: "patch", args: `{"mode":"patch","patch":"*** Add File: a.txt\n*** Delete File: b.txt\n+y"}`,
			want: []string{`write_file {"content":"","path":"a.txt"}`, `delete_file {"path":"b.txt"}`}, wantOK: true},
		{name: "v4a same add path, other content", tool: "patch", args: `{"mode":"patch","patch":"*** Add File: a.txt\n+y\n*** Add File: a.txt\n+z\n*** Add File: a.txt\n+y"}`,
			want: []string{`write_file {"content":"y","path":"a.txt"}`, `write_file {"content":"z","path":"a.txt"}`}, wantOK: true},
		{name: "v4a repeated and lexical duplicate targets", tool: "patch",
			args: `{"mode":"patch","patch":"*** Update File: a.txt\n x\n+y\n*** Update File: a.txt\n x\n+y\n*** Update File: ./a.txt\n x\n+y\n"}`,
			want: []string{`write_file {"content":"x","path":"a.txt"}`, `write_file {"content":"x","path":"./a.txt"}`}, wantOK: true},
		{name: "v4a path with a line break", tool: "patch", args: `{"mode":"patch","path":"c.txt\n*** End Patch","patch":"*** Add File: a.txt\n+y"}`,
			want: unverified, wantOK: true},
		{name: "v4a path with a carriage return", tool: "patch", args: `{"mode":"patch","path":"c.txt\r","patch":"*** Add File: a.txt\n+y"}`,
			want: unverified, wantOK: true},
		{name: "v4a target with a control character", tool: "patch", args: `{"mode":"patch","patch":"*** Add File: a\rb\n+y"}`,
			want: unverified, wantOK: true},
		{name: "v4a target with a line separator", tool: "patch", args: `{"mode":"patch","patch":"*** Add File: a\u2028b\n+y"}`,
			want: unverified, wantOK: true},
		{name: "replace path with NUL", tool: "patch", args: `{"path":"a.txt\u0000","old_string":"x","new_string":"y"}`, want: unverified, wantOK: true},
		{name: "unknown mode", tool: "patch", args: `{"mode":"diff","path":"a.txt","old_string":"x","new_string":"y"}`, want: unverified, wantOK: true},
		{name: "null mode", tool: "patch", args: `{"mode":null,"path":"a.txt","old_string":"x","new_string":"y"}`, want: unverified, wantOK: true},
		{name: "null new string", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":null}`, want: unverified, wantOK: true},
		{name: "path not a string", tool: "patch", args: `{"path":["a.txt"],"old_string":"x","new_string":"y"}`, want: unverified, wantOK: true},
		{name: "replace all not a bool", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y","replace_all":"yes"}`, want: unverified, wantOK: true},
		{name: "repeated key", tool: "patch", args: `{"path":"a.txt","path":"b.txt","old_string":"x","new_string":"y"}`, want: unverified, wantOK: true},
		{name: "v4a unparsable", tool: "patch", args: `{"mode":"patch","patch":"rewrite a.txt please"}`, want: unverified, wantOK: true},
		{name: "not an object", tool: "patch", args: `"a.txt"`, want: unverified, wantOK: true},
		{name: "write_file", tool: "write_file", args: `{"path":"a.txt","content":"y","cross_profile":true}`,
			want: []string{`write_file {"content":"y","path":"a.txt"}`}, wantOK: true},
		{name: "write_file refused by Hermes", tool: "write_file", args: `{"path":"a.txt"}`},
		{name: "other tool", tool: "terminal", args: `{"command":"ls"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			views, ok := HermesTrustedWriteViews(test.tool, json.RawMessage(test.args))
			var got []string
			for _, view := range views {
				got = append(got, view.Tool+" "+string(view.Args))
			}
			if ok != test.wantOK || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %q %t, want %q %t", got, ok, test.want, test.wantOK)
			}
		})
	}
}

// TestHermesTrustedWriteViewsTargetBound pins that a V4A patch naming more
// distinct targets than are judged one by one is the unverified view.
func TestHermesTrustedWriteViewsTargetBound(t *testing.T) {
	body := func(n int) string {
		var b strings.Builder
		for i := 0; i < n-1; i++ {
			fmt.Fprintf(&b, "*** Add File: gen/f%d.txt\n+x\n", i)
		}
		b.WriteString("*** Update File: .git/hooks/pre-commit\n@@\n x\n+y\n")
		return b.String()
	}
	for _, test := range []struct {
		targets   int
		wantViews int
	}{{HermesMaxPatchTargets, HermesMaxPatchTargets}, {HermesMaxPatchTargets + 1, 1}} {
		args, _ := json.Marshal(map[string]any{"mode": "patch", "patch": body(test.targets)})
		views, ok := HermesTrustedWriteViews("patch", args)
		if !ok || len(views) != test.wantViews {
			t.Fatalf("%d targets: %d views, ok=%t; want %d", test.targets, len(views), ok, test.wantViews)
		}
		if last := views[len(views)-1]; test.wantViews == 1 && (last.Tool != "apply_patch" || string(last.Args) != "{}") {
			t.Fatalf("%d targets: got %s %s, want the unverified view", test.targets, last.Tool, last.Args)
		}
	}
}

// TestHermesAddViewContentBound pins that an Add whose text is over the
// bound one written text is judged under carries the stand-in text, so the
// view is judged on its target.
func TestHermesAddViewContentBound(t *testing.T) {
	for _, test := range []struct {
		size int
		want string
	}{{hermesMaxAddContentBytes, "full"}, {hermesMaxAddContentBytes + 1, hermesWriteStandIn}} {
		text := strings.Repeat("a", test.size)
		args, _ := json.Marshal(map[string]any{"mode": "patch", "patch": "*** Add File: a.txt\n+" + text})
		views, ok := HermesTrustedWriteViews("patch", args)
		if !ok || len(views) != 1 {
			t.Fatalf("%d bytes: views %v ok=%t", test.size, views, ok)
		}
		want := test.want
		if want == "full" {
			want = text
		}
		var got map[string]string
		if err := json.Unmarshal(views[0].Args, &got); err != nil || got["content"] != want || got["path"] != "a.txt" {
			t.Fatalf("%d bytes: got %d content bytes (%v), want %d", test.size, len(got["content"]), err, len(want))
		}
	}
}

// TestHermesWriteViewRetarget pins that a view names another spelling of
// its target with its other arguments unchanged.
func TestHermesWriteViewRetarget(t *testing.T) {
	views, ok := HermesTrustedWriteViews("patch", json.RawMessage(`{"path":"/w/a.txt","old_string":"x","new_string":"y"}`))
	if !ok || len(views) != 1 {
		t.Fatalf("views %v ok=%t", views, ok)
	}
	got, ok := views[0].Retarget("a.txt")
	if want := `{"file_path":"a.txt","new_string":"y","old_string":"x"}`; !ok || string(got) != want {
		t.Fatalf("got %s %t, want %s", got, ok, want)
	}
	if _, ok := hermesUnverifiedView().Retarget("a.txt"); ok {
		t.Fatal("the unverified view has no target")
	}
}

// TestHermesV4ATargets pins the reading of a V4A patch as Hermes'
// parse_v4a_patch reads it.
func TestHermesV4ATargets(t *testing.T) {
	w := func(path string) HermesPatchTarget { return HermesPatchTarget{Path: path, Write: true} }
	d := func(path string) HermesPatchTarget { return HermesPatchTarget{Path: path} }
	for _, test := range []struct {
		name, body string
		want       []HermesPatchTarget
	}{
		{name: "update add delete", body: "*** Begin Patch\n*** Update File: a\n@@ f @@\n x\n+y\n*** Add File: /abs/b\n+z\n*** Delete File: ~/c\n*** End Patch\n",
			want: []HermesPatchTarget{w("a"), w("/abs/b"), d("~/c")}},
		{name: "move", body: "*** Move File: a.md  ->  ~/.ssh/authorized_keys\n", want: []HermesPatchTarget{d("a.md"), w("~/.ssh/authorized_keys")}},
		{name: "loose whitespace", body: "***Update \t File: ~/.ssh/authorized_keys \nctx line\n", want: []HermesPatchTarget{w("~/.ssh/authorized_keys")}},
		{name: "crlf", body: "*** Begin Patch\r\n*** Update File: a\r\n+y\r\n*** End Patch\r\n", want: []HermesPatchTarget{w("a")}},
		// Parsing starts after the last Begin line before the first End line.
		{name: "last begin", body: "*** Begin Patch\n*** Update File: a\n+y\n***  Begin  Patch\n*** Update File: b\n+y\n*** End Patch\n*** Update File: c\n+y\n",
			want: []HermesPatchTarget{w("b")}},
		{name: "content lines are not headers", body: "*** Update File: a\n+*** Update File: b\n *** Delete File: c\n", want: []HermesPatchTarget{w("a")}},
		{name: "update without hunk", body: "*** Update File: a\n@@ f @@\n*** Add File: b\n"},
		{name: "update only a no-newline marker", body: "*** Update File: a\n\\ No newline at end of file\n"},
		{name: "empty path", body: "*** Delete File:   \n"},
		{name: "move without destination", body: "*** Move File: a -> \n"},
		{name: "traversal", body: "*** Delete File: x/../../.ssh/authorized_keys\n"},
		{name: "no operations", body: "*** Begin Patch\n*** End Patch\n"},
		{name: "prose", body: "please update a\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, parsed := HermesV4ATargets(test.body)
			if parsed != (test.want != nil) || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %+v parsed=%t, want %+v", got, parsed, test.want)
			}
		})
	}
}
