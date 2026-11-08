// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// withLinkedFile returns the facts of the call with the fact the gateway adds
// for the physical file the call's one operand reaches through a link.
func withLinkedFile(t *testing.T, input Input, physical string) Facts {
	t.Helper()
	facts := Analyze(input)
	operands := facts.OperandPaths()
	if len(operands) != 1 {
		t.Fatalf("want one operand, got %+v", facts.Paths)
	}
	linked := operands[0]
	linked.Value, linked.Normalized, linked.Resolved, linked.Linked = physical, physical, physical, true
	facts.Paths = append(append([]PathFact(nil), facts.Paths...), linked)
	return facts
}

func nativeCall(t *testing.T, tool string, args map[string]any) Input {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Tool: tool, Args: raw}
}

// TestContentProofsReadTheFileALinkReaches pins that a content proof judges
// the text against the physical file the hook client resolved for the link a
// call names, as it does against the protected name: the verdict of a write
// through a link equals the verdict of the write by the protected name.
func TestContentProofsReadTheFileALinkReaches(t *testing.T) {
	t.Parallel()
	const dockerBody = `{"insecure-registries":["http://registry.example.test:5000"]}`
	preloadProfile := func(input Input, facts Facts) bool { return ExactGlobalLDPreloadFileWrite(input, facts) }
	pam := func(input Input, facts Facts) bool {
		_, ok := ExactPAMAuthenticationBypass(input, facts)
		return ok
	}
	cases := []struct {
		name     string
		input    Input
		physical string
		prove    func(Input, Facts) bool
		want     bool
	}{
		{"profile write", nativeCall(t, "Write", map[string]any{"file_path": "/work/profile-link", "content": "export LD_PRELOAD=/usr/local/lib/libx.so\n"}), "/etc/profile.d/gawk.sh", preloadProfile, true},
		{"profile write benign", nativeCall(t, "Write", map[string]any{"file_path": "/work/profile-link", "content": "export EDITOR=vi\n"}), "/etc/profile.d/gawk.sh", preloadProfile, false},
		{"preload file write", nativeCall(t, "Write", map[string]any{"file_path": "/work/preload-link", "content": "/usr/local/lib/libx.so\n"}), "/etc/ld.so.preload", preloadProfile, true},
		{"preload file benign target", nativeCall(t, "Write", map[string]any{"file_path": "/work/preload-link", "content": "/usr/local/lib/libx.so\n"}), "/work/real-file", preloadProfile, false},
		{"pam edit without replace_all", nativeCall(t, "Edit", map[string]any{"file_path": "/work/pam-link", "old_string": "account required pam_nologin.so", "new_string": "auth sufficient pam_permit.so\naccount required pam_nologin.so"}), "/etc/pam.d/sshd", pam, true},
		{"pam edit comment benign", nativeCall(t, "Edit", map[string]any{"file_path": "/work/pam-link", "old_string": "# old", "new_string": "# new"}), "/etc/pam.d/sshd", pam, false},
		{"pam edit of an unprotected file", nativeCall(t, "Edit", map[string]any{"file_path": "/work/pam-link", "old_string": "account required pam_nologin.so", "new_string": "auth sufficient pam_permit.so\naccount required pam_nologin.so"}), "/work/notes", pam, false},
		{"docker write through a link", nativeCall(t, "Write", map[string]any{"file_path": "/work/docker-link", "content": dockerBody}), "/etc/docker/daemon.json", ExactDockerInsecureRegistryWrite, true},
		{"docker benign document through a link", nativeCall(t, "Write", map[string]any{"file_path": "/work/docker-link", "content": `{"log-level":"warn"}`}), "/etc/docker/daemon.json", ExactDockerInsecureRegistryWrite, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := withLinkedFile(t, test.input, test.physical)
			if got := test.prove(test.input, facts); got != test.want {
				t.Fatalf("with the link fact: proof=%t, want %t", got, test.want)
			}
			if test.prove(test.input, Analyze(test.input)) {
				t.Fatal("the same call without the link fact is not a protected write and got a proof")
			}
		})
	}
}

// TestDockerInsecureRegistryProofReadsEveryWholeFileToolSpelling pins that
// the proof for a complete daemon.json document does not depend on the name a
// tool gives the path argument (path, file_path, filePath).
func TestDockerInsecureRegistryProofReadsEveryWholeFileToolSpelling(t *testing.T) {
	t.Parallel()
	const insecure = `{"insecure-registries":["http://registry.example.test:5000"]}`
	for _, tool := range []string{"Write", "write_file", "write-file", "writefile", "create", "write"} {
		for _, key := range []string{"path", "file_path", "filePath"} {
			for body, want := range map[string]bool{insecure: true, `{"log-level":"warn"}`: false} {
				input := nativeCall(t, tool, map[string]any{key: dockerDaemonConfigPath, "content": body})
				facts := Analyze(input)
				if !facts.Authoritative() || !facts.EnforcementEligible() {
					continue // not a call the gateway enforces on
				}
				// Claude Code's Write names its file file_path only.
				if tool == "Write" && key != "file_path" {
					want = false
				}
				if got := ExactDockerInsecureRegistryWrite(input, facts); got != want {
					t.Errorf("%s{%s}: proof=%t, want %t for %s", tool, key, got, want, body)
				}
			}
		}
	}
	input := nativeCall(t, "write_file", map[string]any{"file_path": dockerDaemonConfigPath, "content": insecure})
	if facts := Analyze(input); !facts.Authoritative() || !facts.EnforcementEligible() ||
		!ExactDockerInsecureRegistryWrite(input, facts) {
		t.Fatal("write_file{file_path,content} of an insecure daemon.json received no proof")
	}
}
