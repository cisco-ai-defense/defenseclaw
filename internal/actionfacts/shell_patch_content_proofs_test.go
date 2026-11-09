// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// The content proofs read the literal envelope of an apply_patch command with a
// here-document as they read the apply_patch tool, and read nothing from any
// other shell text. Every delimiter spelling is covered by
// TestContentProofsReadTheEnvelopeOfEveryHereDocumentSpelling.
func TestContentProofsReadTheEnvelopeOfAShellApplyPatch(t *testing.T) {
	const lib = "/usr/local/lib/libreview.so"
	patch := func(directives string) string {
		return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + directives + "*** End Patch\nPATCH\n"
	}
	loader := "*** Add File: /etc/ld.so.preload\n+" + lib + "\n"
	pam := "*** Update File: /etc/pam.d/sshd\n@@\n+auth sufficient pam_permit.so\n"
	docker := "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n"
	sudoers := "*** Add File: /etc/sudoers.d/review\n+reviewer ALL=(ALL) NOPASSWD: ALL\n"
	rows := []struct {
		name, command                string
		loader, pam, docker, sudoers bool
	}{
		{name: "loader", command: patch(loader), loader: true},
		{name: "pam", command: patch(pam), pam: true},
		{name: "docker", command: patch(docker), docker: true},
		{name: "sudoers", command: patch(sudoers), sudoers: true},
		{name: "after an ordinary file", command: patch("*** Add File: notes.txt\n+hello\n" + loader), loader: true},
		{name: "two patches", command: patch("*** Add File: notes.txt\n+hello\n") + patch(loader), loader: true},
		{name: "command after the patch", command: patch(loader) + "cat notes.txt\n", loader: true},
		{name: "ordinary file", command: patch("*** Add File: notes.txt\n+hello\n")},
		{name: "redirect is not a patch", command: "echo " + lib + " > /etc/ld.so.preload\n"},
		{name: "unquoted delimiter", loader: true, command: "apply_patch <<PATCH\n*** Begin Patch\n" + loader + "*** End Patch\nPATCH\n"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, tool := range []string{"Bash", "exec_command"} {
				input := Input{Tool: tool, Command: row.command, CWD: "/tmp"}
				facts := Analyze(input)
				_, pamProven := ExactPAMAuthenticationBypass(input, facts)
				got := [4]bool{
					ExactGlobalLDPreloadFileWrite(input, facts), pamProven,
					ExactDockerInsecureRegistryWrite(input, facts), ExactPOSIXUnrestrictedSudoersGrantWrite(facts),
				}
				if want := [4]bool{row.loader, row.pam, row.docker, row.sudoers}; got != want {
					t.Fatalf("%s: loader, pam, docker, sudoers = %v, want %v", tool, got, want)
				}
			}
		})
	}
}

// A target the hook client placed on a physical file is judged as that file
// alone; only a directory it gave no usable answer for places the target
// lexically.
func TestClientPlacementOfATargetIsLexicalOnlyWithoutAnAnswer(t *testing.T) {
	input := Input{
		CWD: "/work/proj",
		ClientResolvedTargets: map[string]string{
			"/work/proj/lnk":    "/home/user/notes.txt",
			"/work/proj/broken": "",
		},
	}
	for name, want := range map[string][]string{
		"lnk":    {"/home/user/notes.txt"},
		"other":  {"/work/proj/other"},
		"broken": {"/work/proj/broken"},
	} {
		if got := nativeClientReachedFiles(input, name); !slices.Equal(got, want) {
			t.Errorf("%s: files = %v, want %v", name, got, want)
		}
	}
}
