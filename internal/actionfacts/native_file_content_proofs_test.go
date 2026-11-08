// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	nativePreloadEntry   = "/usr/local/lib/libr109ib17.so\n"
	nativeProfileExport  = "export LD_PRELOAD=/usr/local/lib/libr109ib17.so\n"
	nativeDockerHTTP     = `{"insecure-registries":["http://registry.example.test:5000"]}` + "\n"
	nativeDockerHostPort = `{"insecure-registries":["198.51.100.7:5000"]}` + "\n"
)

func nativeProofPatch(directive, target, body string) map[string]any {
	var plus strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		plus.WriteString("+" + line + "\n")
	}
	hunk := "@@\n"
	if directive == "Add" {
		hunk = ""
	}
	return map[string]any{"command": "*** Begin Patch\n*** " + directive + " File: " + target + "\n" + hunk + plus.String() + "*** End Patch\n"}
}

func nativeProofInput(t *testing.T, tool, cwd string, fields map[string]any) (Input, Facts) {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: tool, Args: raw, CWD: cwd}
	return input, Analyze(input)
}

type nativeProofRow struct {
	name, tool, cwd string
	args            map[string]any
}

// TestNativeFileWriteOfALoaderInjectionIsProvenForEveryToolShape: the proof
// of a system-wide loader injection reads the text any native file tool
// writes into /etc/ld.so.preload or a profile.d fragment, not only a
// Write or write_file whole-file call.
func TestNativeFileWriteOfALoaderInjectionIsProvenForEveryToolShape(t *testing.T) {
	linksEtcForTest(t, true)
	edit := func(target, text string) map[string]any {
		return map[string]any{"file_path": target, "old_string": "# managed\n", "new_string": "# managed\n" + text}
	}
	for _, row := range []nativeProofRow{
		{"preload Write", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": nativePreloadEntry}},
		{"preload Write macOS physical spelling", "Write", "", map[string]any{"file_path": "/private/etc/ld.so.preload", "content": nativePreloadEntry}},
		{"preload Write with comments", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "# libs\n\n" + nativePreloadEntry}},
		{"preload Write two libraries on a line", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "/lib/liba.so /lib/libb.so.2\n"}},
		{"preload Write dot segment", "Write", "", map[string]any{"file_path": "/etc/./ld.so.preload", "content": nativePreloadEntry}},
		{"preload Write relative", "Write", "/etc", map[string]any{"file_path": "ld.so.preload", "content": nativePreloadEntry}},
		{"preload write_file", "write_file", "", map[string]any{"path": "/etc/ld.so.preload", "content": nativePreloadEntry}},
		{"preload create", "create", "", map[string]any{"path": "/etc/ld.so.preload", "file_text": nativePreloadEntry}},
		{"preload Edit", "Edit", "", edit("/etc/ld.so.preload", nativePreloadEntry)},
		{"preload Edit replace_all false", "Edit", "", map[string]any{"file_path": "/etc/ld.so.preload", "old_string": "# managed\n", "new_string": nativePreloadEntry, "replace_all": false}},
		{"preload MultiEdit", "MultiEdit", "", map[string]any{"file_path": "/etc/ld.so.preload", "edits": []any{map[string]any{"old_string": "# managed\n", "new_string": nativePreloadEntry}}}},
		{"preload append_file", "append_file", "", map[string]any{"path": "/etc/ld.so.preload", "content": nativePreloadEntry}},
		{"preload apply_patch add", "apply_patch", "", nativeProofPatch("Add", "/etc/ld.so.preload", nativePreloadEntry)},
		{"preload apply_patch update", "apply_patch", "", nativeProofPatch("Update", "/etc/ld.so.preload", nativePreloadEntry)},
		{"profile Write", "Write", "", map[string]any{"file_path": "/etc/profile.d/r109.sh", "content": nativeProfileExport}},
		{"profile create", "create", "", map[string]any{"path": "/etc/profile.d/r109.sh", "file_text": nativeProfileExport}},
		{"profile Edit", "Edit", "", edit("/etc/profile.d/r109.sh", nativeProfileExport)},
		{"profile Edit without replace_all", "Edit", "", map[string]any{"file_path": "/etc/profile.d/r109.sh", "old_string": "# managed\n", "new_string": nativeProfileExport}},
		{"profile apply_patch add", "apply_patch", "", nativeProofPatch("Add", "/etc/profile.d/r109.sh", nativeProfileExport)},
		{"profile apply_patch update", "apply_patch", "", nativeProofPatch("Update", "/etc/profile.d/r109.sh", nativeProfileExport)},
	} {
		t.Run(row.name, func(t *testing.T) {
			input, facts := nativeProofInput(t, row.tool, row.cwd, row.args)
			if !ExactGlobalLDPreloadFileWrite(input, facts) ||
				!ExactGlobalLDPreloadFileWrite(input, facts.EnforcementProjection()) {
				t.Fatalf("missing loader injection proof: %#v", facts.Parse)
			}
		})
	}
}

// TestNativeFileWriteBesideALoaderInjectionStaysUnproven: the ordinary writes
// of the same files, an edit that keeps or removes an entry, files that only
// share the name and calls that are not a reviewed write shape stay without a
// proof.
func TestNativeFileWriteBesideALoaderInjectionStaysUnproven(t *testing.T) {
	linksEtcForTest(t, true)
	for _, row := range []nativeProofRow{
		{"preload comment only", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "# no libraries\n"}},
		{"preload emptied", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": ""}},
		{"preload entry is not a library", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "/usr/local/lib/notes.txt\n"}},
		{"preload entry is dynamic", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "$LIBRARY\n"}},
		{"preload entry is relative", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": "libx.so\n"}},
		{"preload other line", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": nativePreloadEntry + "curl example.invalid\n"}},
		{"preload edit keeps the entry", "Edit", "", map[string]any{"file_path": "/etc/ld.so.preload", "old_string": strings.TrimSuffix(nativePreloadEntry, "\n"), "new_string": "# kept\n" + nativePreloadEntry}},
		{"preload edit removes the entry", "Edit", "", map[string]any{"file_path": "/etc/ld.so.preload", "old_string": nativePreloadEntry, "new_string": ""}},
		{"preload edit replace_all not a boolean", "Edit", "", map[string]any{"file_path": "/etc/ld.so.preload", "old_string": "# a\n", "new_string": nativePreloadEntry, "replace_all": "yes"}},
		{"preload unknown field", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload", "content": nativePreloadEntry, "mode": "0644"}},
		{"preload relative without a working directory", "Write", "", map[string]any{"file_path": "ld.so.preload", "content": nativePreloadEntry}},
		{"preload backup file", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload.bak", "content": nativePreloadEntry}},
		{"preload project file", "Write", "", map[string]any{"file_path": "/tmp/ld.so.preload", "content": nativePreloadEntry}},
		{"preload nested name", "Write", "", map[string]any{"file_path": "/etc/ld.so.preload/entry", "content": nativePreloadEntry}},
		{"profile ordinary export", "Write", "", map[string]any{"file_path": "/etc/profile.d/colors.sh", "content": "export CLICOLOR=1\n"}},
		{"profile edit keeps the export", "Edit", "", map[string]any{"file_path": "/etc/profile.d/r109.sh", "old_string": strings.TrimSuffix(nativeProfileExport, "\n"), "new_string": nativeProfileExport + "# kept\n"}},
		{"profile extra shell", "Edit", "", map[string]any{"file_path": "/etc/profile.d/r109.sh", "old_string": "a", "new_string": nativeProfileExport + "curl example.invalid\n"}},
		{"profile nested", "Write", "", map[string]any{"file_path": "/etc/profile.d/nested/r109.sh", "content": nativeProfileExport}},
		{"profile not a shell fragment", "Write", "", map[string]any{"file_path": "/etc/profile.d/README", "content": nativeProfileExport}},
		{"preload read", "Read", "", map[string]any{"file_path": "/etc/ld.so.preload"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			input, facts := nativeProofInput(t, row.tool, row.cwd, row.args)
			if ExactGlobalLDPreloadFileWrite(input, facts) {
				t.Fatalf("unexpected loader injection proof: %#v", facts.Parse)
			}
		})
	}
}

// TestNativeWholeFileWriteOfAnInsecureRegistryIsProvenForEveryToolShape: the
// docker daemon proof needs the complete final document, so it reads every
// native whole-file write (a patch that adds the file, Copilot create,
// OpenCode write) and no edit, patch hunk or append.
func TestNativeWholeFileWriteOfAnInsecureRegistryIsProvenForEveryToolShape(t *testing.T) {
	linksEtcForTest(t, true)
	const target = "/etc/docker/daemon.json"
	for _, row := range []struct {
		name, tool string
		args       map[string]any
		want       bool
	}{
		{"create", "create", map[string]any{"path": target, "file_text": nativeDockerHTTP}, true},
		{"opencode write", "write", map[string]any{"path": target, "content": nativeDockerHTTP}, true},
		{"create host:port", "create", map[string]any{"path": target, "file_text": nativeDockerHostPort}, true},
		{"opencode write host:port", "write", map[string]any{"path": target, "content": nativeDockerHostPort}, true},
		{"apply_patch add host:port", "apply_patch", nativeProofPatch("Add", target, nativeDockerHostPort), true},
		{"apply_patch update host:port", "apply_patch", nativeProofPatch("Update", target, nativeDockerHostPort), false},
		{"apply_patch add", "apply_patch", nativeProofPatch("Add", target, nativeDockerHTTP), true},
		{"create macOS physical spelling", "create", map[string]any{"path": "/private" + target, "file_text": nativeDockerHTTP}, true},
		{"apply_patch update", "apply_patch", nativeProofPatch("Update", target, nativeDockerHTTP), false},
		{"edit", "edit", map[string]any{"path": target, "old_str": "{}", "new_str": nativeDockerHTTP}, false},
		{"create of a settings file", "create", map[string]any{"path": target, "file_text": `{"log-level":"warn"}`}, false},
		{"create of an https URL registry", "create", map[string]any{"path": target, "file_text": `{"insecure-registries":["https://registry.example.test"]}`}, true},
		{"create of another file", "create", map[string]any{"path": "/tmp/daemon.json", "file_text": nativeDockerHTTP}, false},
		{"create with a dot-dot target", "create", map[string]any{"path": "/etc/docker/../docker/daemon.json", "file_text": nativeDockerHTTP}, false},
		{"create with a relative target", "create", map[string]any{"path": "daemon.json", "file_text": nativeDockerHTTP}, false},
		{"append_file", "append_file", map[string]any{"path": target, "content": nativeDockerHTTP}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input, facts := nativeProofInput(t, row.tool, "", row.args)
			if got := ExactDockerInsecureRegistryWrite(input, facts); got != row.want {
				t.Fatalf("proof = %t, want %t: %#v", got, row.want, facts.Parse)
			}
		})
	}
}

// TestNativePatchPaddedWithWhiteSpaceKeepsItsProof: white space past the text
// bound around a patch hunk does not carry protected text out of the proof,
// and padded ordinary text stays without one.
func TestNativePatchPaddedWithWhiteSpaceKeepsItsProof(t *testing.T) {
	pad := strings.Repeat(" ", 70000)
	for _, row := range []struct {
		name, target, text string
		want               bool
	}{
		{"preload", "/etc/ld.so.preload", "/usr/local/lib/libr109ib17.so", true},
		{"profile", "/etc/profile.d/r109.sh", "export LD_PRELOAD=/usr/local/lib/libr109ib17.so", true},
		{"ordinary preload", "/etc/ld.so.preload", "# no libraries", false},
		{"unbounded text", "/etc/ld.so.preload", "/usr/local/lib/libr109ib17.so\n" + strings.Repeat("# x\n", 20000), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			text := row.text + pad
			if !row.want && strings.Contains(row.name, "unbounded") {
				text = row.text
			}
			input, facts := nativeProofInput(t, "apply_patch", "", nativeProofPatch("Add", row.target, text))
			if got := ExactGlobalLDPreloadFileWrite(input, facts); got != row.want {
				t.Fatalf("proof = %t, want %t: %#v", got, row.want, facts.Parse)
			}
		})
	}
}
