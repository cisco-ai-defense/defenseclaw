// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

const daemonConfigTarget = "/etc/docker/daemon.json"

func dockerEditCall(t *testing.T, tool string, args map[string]any, content *string) bool {
	t.Helper()
	input, facts := nativeProofInput(t, tool, "", args)
	if content != nil {
		input.ClientNativeFileContents = map[string]string{daemonConfigTarget: *content}
	}
	return ExactDockerInsecureRegistryWrite(input, facts)
}

func multiEdit(steps ...[2]string) map[string]any {
	edits := make([]any, 0, len(steps))
	for _, step := range steps {
		edits = append(edits, map[string]any{"old_string": step[0], "new_string": step[1]})
	}
	return map[string]any{"file_path": daemonConfigTarget, "edits": edits}
}

// TestDockerEditOfAReadFileIsJudgedOnTheDocumentItLeaves: when the gateway
// read the file, an Edit or MultiEdit is applied to it as the tool applies it
// and the document it leaves is judged as a Write of that document is; the
// steps are never read on their own, joined or overlapped.
func TestDockerEditOfAReadFileIsJudgedOnTheDocumentItLeaves(t *testing.T) {
	linksEtcForTest(t, true)
	empty := func(text string) *string { return &text }
	for _, row := range []struct {
		name, tool string
		args       map[string]any
		content    *string
		want       bool
	}{
		{
			// The closing characters of the first step's text are the opening
			// characters of the second step's replaced text, in different places.
			"empty insecure list then a distinct dns list that ends the same way", "MultiEdit",
			multiEdit([2]string{`{"x":1`, `{"insecure-registries":[]`}, [2]string{`[]}`, `["8.8.8.8"]}`}),
			empty(`{"x":1,"dns":[]}`), false,
		},
		{
			"empty insecure list then a distinct mirrors list that ends the same way", "MultiEdit",
			multiEdit([2]string{`{"x":1`, `{"insecure-registries":[]`}, [2]string{`[]}`, `["https://mirror.example.test:5000"]}`}),
			empty(`{"x":1,"registry-mirrors":[]}`), false,
		},
		{
			"the same empty insecure list opened by one step and filled by the next", "MultiEdit",
			multiEdit([2]string{`{"x":1,"insecure-registries":`, `{"insecure-registries":`}, [2]string{`[]}`, `["198.51.100.7:5000"]}`}),
			empty(`{"x":1,"insecure-registries":[]}`), true,
		},
		{
			"a step adds a registry and a later step takes it out", "MultiEdit",
			multiEdit(
				[2]string{`{"debug":true}`, `{"insecure-registries":["198.51.100.7:5000"]}`},
				[2]string{`["198.51.100.7:5000"]`, `[]`}),
			empty(`{"debug":true}`), false,
		},
		{
			"a step moves the registry to a key that is not the list", "MultiEdit",
			multiEdit(
				[2]string{`{"debug":true}`, `{"insecure-registries":["198.51.100.7:5000"]}`},
				[2]string{`"insecure-registries"`, `"registry-mirrors"`}),
			empty(`{"debug":true}`), false,
		},
		{
			"an edit that only changes the log level", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `"warn"`, "new_string": `"debug"`},
			empty(`{"log-level":"warn"}`), false,
		},
		{
			"an edit that fills the list with a registry", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `"insecure-registries":[]`, "new_string": `"insecure-registries":["10.0.0.0/8"]`},
			empty(`{"insecure-registries":[],"debug":true}`), true,
		},
		{
			"an edit that fills the list with a loopback registry", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `[]`, "new_string": `["127.0.0.1:5000"]`},
			empty(`{"insecure-registries":[]}`), false,
		},
		{
			"an edit that only deletes text and so turns a name into the list key", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `-off`, "new_string": ``},
			empty(`{"insecure-registries-off":["198.51.100.7:5000"]}`), true,
		},
		{
			"an edit that replaces every occurrence", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `tmp`, "new_string": `198.51.100.7:5000`, "replace_all": true},
			empty(`{"insecure-registries":["tmp","tmp"]}`), true,
		},
		{
			"an empty replaced text over an absent file creates the file", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": ``, "new_string": `{"insecure-registries":["198.51.100.7:5000"]}`},
			empty(``), true,
		},
		{
			"a camelCase Edit", "Edit",
			map[string]any{"filePath": daemonConfigTarget, "oldString": `[]`, "newString": `["198.51.100.7:5000"]`},
			empty(`{"insecure-registries":[]}`), true,
		},
		{
			"a Copilot edit", "edit",
			map[string]any{"path": daemonConfigTarget, "old_str": `[]`, "new_str": `["198.51.100.7:5000"]`},
			empty(`{"insecure-registries":[]}`), true,
		},
		{
			// The file is not a document dockerd reads; a Write of it is not judged either.
			"an edit that leaves a file that is not JSON", "Edit",
			map[string]any{"file_path": daemonConfigTarget, "old_string": `[]`, "new_string": `["198.51.100.7:5000"`},
			empty(`{"insecure-registries":[]}`), false,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := dockerEditCall(t, row.tool, row.args, row.content); got != row.want {
				t.Fatalf("proof = %t, want %t", got, row.want)
			}
		})
	}
}

// TestDockerEditOfAnUnreadFileKeepsTheStepReading: an edit whose steps do not
// apply to the file text (a text the file does not hold, more than once
// without replace-all, a file past the bound) or whose file was not read is
// judged on the text the call carries, as before.
func TestDockerEditOfAnUnreadFileKeepsTheStepReading(t *testing.T) {
	linksEtcForTest(t, true)
	text := func(value string) *string { return &value }
	registryEdit := map[string]any{
		"file_path": daemonConfigTarget, "old_string": `{}`,
		"new_string": `{"insecure-registries":["198.51.100.7:5000"]}`,
	}
	oversize := `{"debug":true,"pad":"` + strings.Repeat("x", NativeEditContentLimit) + `"}`
	for _, row := range []struct {
		name    string
		args    map[string]any
		content *string
		want    bool
	}{
		{"file not read", registryEdit, nil, true},
		{"absent file and a text it cannot hold", registryEdit, text(""), true},
		{"file with text that does not hold the replaced text", registryEdit, text(`{"debug":true}`), true},
		{"replaced text found twice without replace-all", map[string]any{
			"file_path": daemonConfigTarget, "old_string": `[]`,
			"new_string": `[],"insecure-registries":["198.51.100.7:5000"]`,
		}, text(`{"dns":[],"insecure-registries":[]}`), true},
		{"file past the bound", map[string]any{
			"file_path": daemonConfigTarget, "old_string": `"debug"`,
			"new_string": `"insecure-registries":["198.51.100.7:5000"],"debug"`,
		}, text(oversize), true},
		{"benign edit of a file not read", map[string]any{
			"file_path": daemonConfigTarget, "old_string": `"warn"`, "new_string": `"debug"`,
		}, nil, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := dockerEditCall(t, "Edit", row.args, row.content); got != row.want {
				t.Fatalf("proof = %t, want %t", got, row.want)
			}
		})
	}
}

// TestDockerEditOfAReadFileThroughALinkIsJudgedOnTheDocument: the file read
// for a link is the physical file, keyed by the name the call gave.
func TestDockerEditOfAReadFileThroughALinkIsJudgedOnTheDocument(t *testing.T) {
	linksEtcForTest(t, true)
	const link = "/work/docker-link"
	args := func(newText string) map[string]any {
		return map[string]any{"file_path": link, "old_string": `[]`, "new_string": newText}
	}
	for _, row := range []struct {
		name, text string
		want       bool
	}{
		{"registry", `["198.51.100.7:5000"]`, true},
		{"empty list", `[]`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := nativeCall(t, "Edit", args(row.text))
			input.ClientResolvedTargets = map[string]string{link: daemonConfigTarget}
			input.ClientNativeFileContents = map[string]string{link: `{"insecure-registries":[]}`}
			facts := withLinkedFile(t, input, daemonConfigTarget)
			if got := ExactDockerInsecureRegistryWrite(input, facts); got != row.want {
				t.Fatalf("proof = %t, want %t", got, row.want)
			}
		})
	}
}

// TestDockerDaemonConfigEditFilesNamesTheFileAnEditChanges: only an Edit or a
// MultiEdit of the daemon configuration, by its own name or through a link
// the client answered, asks for a file text.
func TestDockerDaemonConfigEditFilesNamesTheFileAnEditChanges(t *testing.T) {
	linksEtcForTest(t, true)
	edit := func(target string) map[string]any {
		return map[string]any{"file_path": target, "old_string": "a", "new_string": "b"}
	}
	linked := func(input Input) Input {
		input.ClientResolvedTargets = map[string]string{"/work/docker-link": daemonConfigTarget}
		return input
	}
	for _, row := range []struct {
		name  string
		input Input
		want  map[string]string
	}{
		{"edit", nativeCall(t, "Edit", edit(daemonConfigTarget)), map[string]string{daemonConfigTarget: daemonConfigTarget}},
		{"edit by a dot-dot name", nativeCall(t, "Edit", edit("/etc/docker/../docker/daemon.json")), map[string]string{daemonConfigTarget: daemonConfigTarget}},
		{"multi edit", nativeCall(t, "MultiEdit", multiEdit([2]string{"a", "b"})), map[string]string{daemonConfigTarget: daemonConfigTarget}},
		{"edit through a link", linked(nativeCall(t, "Edit", edit("/work/docker-link"))), map[string]string{"/work/docker-link": daemonConfigTarget}},
		{"edit through a link nobody answered", nativeCall(t, "Edit", edit("/work/docker-link")), nil},
		{"edit of another file", nativeCall(t, "Edit", edit("/etc/docker/key.json")), nil},
		{"write", nativeCall(t, "Write", map[string]any{"file_path": daemonConfigTarget, "content": "{}"}), nil},
		{"patch", nativeCall(t, "apply_patch", nativeProofPatch("Update", daemonConfigTarget, "{}")), nil},
		{"shell command", Input{Tool: "Bash", Command: "echo hi"}, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := DockerDaemonConfigEditFiles(row.input)
			if len(got) != len(row.want) || !slices.Equal(mapKeysValues(got), mapKeysValues(row.want)) {
				t.Fatalf("files = %v, want %v", got, row.want)
			}
		})
	}
}

func mapKeysValues(files map[string]string) []string {
	var out []string
	for key, value := range files {
		out = append(out, key+"="+value)
	}
	slices.Sort(out)
	return out
}
