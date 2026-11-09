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
)

const dockerDaemonConfigForTest = "/etc/docker/daemon.json"

// The tests never read the host's files: a file is unreadable unless a test
// gives it.
func init() {
	readNativeEditFile = func(string) (string, bool) { return "", false }
}

func stubNativeEditFiles(t *testing.T, files map[string]string) {
	t.Helper()
	previous := readNativeEditFile
	readNativeEditFile = func(name string) (string, bool) {
		text, ok := files[name]
		return text, ok
	}
	t.Cleanup(func() { readNativeEditFile = previous })
}

func dockerMultiEdit(t *testing.T, steps ...[2]string) actionfacts.Input {
	t.Helper()
	edits := make([]any, 0, len(steps))
	for _, step := range steps {
		edits = append(edits, map[string]any{"old_string": step[0], "new_string": step[1]})
	}
	return exactStructuredInput(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigForTest, "edits": edits})
}

// TestDockerEditOfAFileTheGatewayReadsIsJudgedOnTheDocumentItLeaves: an
// ordinary MultiEdit whose steps share closing characters in different places
// of the file is allowed in every profile, as the Write of the document it
// leaves is, and the same edit that fills the one empty insecure list is
// blocked (strict, default) or alerted (permissive).
func TestDockerEditOfAFileTheGatewayReadsIsJudgedOnTheDocumentItLeaves(t *testing.T) {
	blocked := map[string]string{"default": "block", "permissive": "alert", "strict": "block"}
	wide := strings.Repeat(" ", 72)
	for _, test := range []struct {
		name    string
		input   actionfacts.Input
		file    string
		actions map[string]string
	}{
		{
			"empty insecure list then a distinct dns list",
			dockerMultiEdit(t, [2]string{`{"x":1`, `{"insecure-registries":[]`}, [2]string{`[]}`, `["8.8.8.8"]}`}),
			`{"x":1,"dns":[]}`, nil,
		},
		{
			"empty insecure list then a distinct mirrors list",
			dockerMultiEdit(t, [2]string{`{"x":1`, `{"insecure-registries":[]`}, [2]string{`[]}`, `["https://mirror.example.test:5000"]}`}),
			`{"x":1,"registry-mirrors":[]}`, nil,
		},
		{
			"the one insecure list opened by a step and filled by the next",
			dockerMultiEdit(t, [2]string{`{"x":1,"insecure-registries":`, `{"insecure-registries":`}, [2]string{`[]}`, `["198.51.100.7:5000"]}`}),
			`{"x":1,"insecure-registries":[]}`, blocked,
		},
		{
			"an edit of an absent file that creates the document",
			exactStructuredInput(t, "Edit", map[string]any{
				"file_path": dockerDaemonConfigForTest, "old_string": "",
				"new_string": `{"insecure-registries":["10.0.0.0/8"]}`,
			}),
			"", blocked,
		},
		{
			"a registry listed in an empty file and taken out by the next step",
			dockerMultiEdit(t, [2]string{``, `{"insecure-registries":["198.51.100.7:5000"]}`}, [2]string{`"198.51.100.7:5000"`, ``}),
			"", nil,
		},
		{
			"a first step whose text the readable file does not hold",
			dockerMultiEdit(t, [2]string{`"absent":1`, `"insecure-registries":["198.51.100.7:5000"]`}, [2]string{`[]`, `["8.8.8.8"]`}),
			`{"registry-mirrors":[]}`, nil,
		},
		{
			// A valid 60 KiB document; the steps spread its white space past the
			// work limit, bring it back and rename the list key.
			"a transient text past the work limit and a protected final document",
			dockerReplaceAllEdit(t, [2]string{` `, wide}, [2]string{wide, ` `}, [2]string{`insecure-registriez`, `insecure-registries`}),
			`{"insecure-registriez":["198.51.100.7:5000"]}` + strings.Repeat(" ", 60000), blocked,
		},
		{
			"an edit that the tool refuses over a file of white space only",
			exactStructuredInput(t, "Edit", map[string]any{
				"file_path": dockerDaemonConfigForTest, "old_string": `"debug":false`,
				"new_string": `"insecure-registries":["198.51.100.7:5000"]`,
			}),
			"  \n", nil,
		},
		{
			"a one-step edit whose text the readable file does not hold",
			exactStructuredInput(t, "Edit", map[string]any{
				"file_path": dockerDaemonConfigForTest, "old_string": `"debug":false`,
				"new_string": `"insecure-registries":["198.51.100.7:5000"]`,
			}),
			`{"debug":true}`, nil,
		},
	} {
		for profile, want := range map[string]string{"default": "", "permissive": "", "strict": ""} {
			_ = want
			t.Run(test.name+"/"+profile, func(t *testing.T) {
				stubNativeEditFiles(t, map[string]string{dockerDaemonConfigForTest: test.file})
				connector := "docker-edit-document-" + profile
				installToolCallCorpusProfileConnector(t, connector, profile)
				result := EvaluateDeterministicAction(
					t.Context(), test.input, string(test.input.Args), connector, profile,
				)
				matched := slices.Contains(result.RuleIDs, dockerInsecureHTTPRegistryRuleID)
				if test.actions == nil {
					if matched {
						t.Fatalf("benign edit matched %s: %+v", dockerInsecureHTTPRegistryRuleID, result)
					}
					return
				}
				if !matched || result.Action != test.actions[profile] {
					t.Fatalf("result=%+v, want %s action %s", result, dockerInsecureHTTPRegistryRuleID, test.actions[profile])
				}
			})
		}
	}
}

func dockerReplaceAllEdit(t *testing.T, steps ...[2]string) actionfacts.Input {
	t.Helper()
	edits := make([]any, 0, len(steps))
	for _, step := range steps {
		edits = append(edits, map[string]any{"old_string": step[0], "new_string": step[1], "replace_all": true})
	}
	return exactStructuredInput(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigForTest, "edits": edits})
}

// TestDockerEditOfAFileTheGatewayCannotReadKeepsTheStepReading: the same
// protected edit is judged on the text the call carries when the file is not
// read, and the file is read only when the call edits the daemon configuration.
func TestDockerEditOfAFileTheGatewayCannotReadKeepsTheStepReading(t *testing.T) {
	input := dockerMultiEdit(t, [2]string{`{"x":1,"insecure-registries":`, `{"insecure-registries":`}, [2]string{`[]}`, `["198.51.100.7:5000"]}`})
	connector := "docker-edit-document-unread"
	installToolCallCorpusProfileConnector(t, connector, "default")
	result := EvaluateDeterministicAction(t.Context(), input, string(input.Args), connector, "default")
	if !slices.Contains(result.RuleIDs, dockerInsecureHTTPRegistryRuleID) || result.Action != "block" {
		t.Fatalf("unread file: result=%+v", result)
	}
}

func TestWithNativeEditFileContents(t *testing.T) {
	stubNativeEditFiles(t, map[string]string{dockerDaemonConfigForTest: `{"debug":true}`})
	edit := func(target string) actionfacts.Input {
		return exactStructuredInput(t, "Edit", map[string]any{"file_path": target, "old_string": "a", "new_string": "b"})
	}
	for _, test := range []struct {
		name    string
		request trustedActionRequest
		want    map[string]string
	}{
		{"edit of the daemon configuration", trustedActionRequest{Input: edit(dockerDaemonConfigForTest)},
			map[string]string{dockerDaemonConfigForTest: `{"debug":true}`}},
		{"multi edit of the daemon configuration", trustedActionRequest{Input: dockerMultiEdit(t, [2]string{"a", "b"})},
			map[string]string{dockerDaemonConfigForTest: `{"debug":true}`}},
		{"edit of another file", trustedActionRequest{Input: edit("/etc/docker/key.json")}, nil},
		{"write of the daemon configuration", trustedActionRequest{Input: exactStructuredInput(t, "Write",
			map[string]any{"file_path": dockerDaemonConfigForTest, "content": "{}"})}, nil},
		{"action that runs elsewhere", trustedActionRequest{Input: edit(dockerDaemonConfigForTest), SkipLocalFilesystemResolution: true}, nil},
		{"edit through a link the client answered", trustedActionRequest{Input: func() actionfacts.Input {
			input := edit("/work/docker-link")
			input.ClientResolvedTargets = map[string]string{"/work/docker-link": dockerDaemonConfigForTest}
			return input
		}()}, map[string]string{"/work/docker-link": `{"debug":true}`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := withNativeEditFileContents(test.request)
			if len(got) != len(test.want) {
				t.Fatalf("contents = %v, want %v", got, test.want)
			}
			for key, text := range test.want {
				if got[key] != text {
					t.Fatalf("contents = %v, want %v", got, test.want)
				}
			}
		})
	}
	t.Run("file that cannot be read", func(t *testing.T) {
		stubNativeEditFiles(t, nil)
		if got := withNativeEditFileContents(trustedActionRequest{Input: edit(dockerDaemonConfigForTest)}); got != nil {
			t.Fatalf("contents = %v, want none", got)
		}
	})
}

// TestNativeEditFileIsReadOnlyWhereTheGatewayCanPlaceIt: the gateway reads
// the file of a POSIX path on a POSIX host and nothing on Windows, where the
// path is not the daemon configuration; the rest of the file tests run the
// same way on every host through the stubbed reader.
func TestNativeEditFileIsReadOnlyWhereTheGatewayCanPlaceIt(t *testing.T) {
	name := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(name, []byte(`{"debug":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for goos, want := range map[string]bool{"linux": true, "darwin": true, "windows": false} {
		text, ok := readNativeEditFileOn(goos, name)
		if ok != want || (ok && text != `{"debug":true}`) || (!ok && text != "") {
			t.Fatalf("%s: read = (%q, %t), want ok %t", goos, text, ok, want)
		}
		missing, ok := readNativeEditFileOn(goos, name+".absent")
		if ok != want || missing != "" {
			t.Fatalf("%s absent file: read = (%q, %t), want ok %t", goos, missing, ok, want)
		}
	}
}

func TestReadBoundedTextFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		name = filepath.Join(dir, name)
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	for _, test := range []struct {
		name, file, want string
		ok               bool
	}{
		{"text", write("daemon.json", `{"debug":true}`), `{"debug":true}`, true},
		{"empty file", write("empty.json", ""), "", true},
		{"absent file", filepath.Join(dir, "absent.json"), "", true},
		{"at the bound", write("bound.json", strings.Repeat("x", actionfacts.NativeEditContentLimit)),
			strings.Repeat("x", actionfacts.NativeEditContentLimit), true},
		{"past the bound", write("big.json", strings.Repeat("x", actionfacts.NativeEditContentLimit+1)), "", false},
		{"directory", dir, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := readBoundedTextFile(test.file)
			if ok != test.ok || got != test.want {
				t.Fatalf("read = (%d bytes, %t), want (%d bytes, %t)", len(got), ok, len(test.want), test.ok)
			}
		})
	}
}
