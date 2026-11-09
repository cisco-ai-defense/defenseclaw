// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// The content proofs read the literal envelope of an apply_patch command with a
// quoted here-document as they read the apply_patch tool, and read nothing
// from any other shell text.
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
		{name: "not a literal envelope", command: "apply_patch <<PATCH\n*** Begin Patch\n" + loader + "*** End Patch\nPATCH\n"},
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

// A call of a function the action defined runs that function and no program of
// its name: the patch text it is given is no patch the proofs read, and the
// statements of the function body are judged as the commands they are. A call
// the action may still send to the program (a definition after the call, in a
// condition or in a block, a name unset, eval or sourced, a command or env
// wrapper, a function that forwards to the program) is read as the program.
func TestContentProofsReadNoPatchInTheCallOfADefinedFunction(t *testing.T) {
	const patch = "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\nPATCH\n"
	rows := []struct {
		name, command string
		loader        bool
	}{
		{name: "program alone", command: patch, loader: true},
		{name: "function that does nothing", command: "apply_patch() { :; }\n" + patch},
		{name: "function that writes an ordinary file", command: "apply_patch() { cat > notes.txt; }\n" + patch},
		{name: "function keyword spelling", command: "apply_patch() { cat > notes.txt\n}\ncd /tmp && " + patch},
		{name: "function defined after the call", command: patch + "apply_patch() { :; }\n", loader: true},
		{name: "function defined in a condition", command: "[ -n \"$X\" ] && apply_patch() { :; }\n" + patch, loader: true},
		{name: "function defined in a block", command: "{ apply_patch() { :; }; }\n" + patch, loader: true},
		{name: "function defined in a subshell", command: "( apply_patch() { :; } )\n" + patch, loader: true},
		{name: "function unset", command: "apply_patch() { :; }\nunset -f apply_patch\n" + patch, loader: true},
		{name: "function unset by eval", command: "apply_patch() { :; }\neval \"un\"\"set -f apply_patch\"\n" + patch, loader: true},
		{name: "function redefined by eval", command: "apply_patch() { :; }\neval \"$X\"\n" + patch},
		{name: "function redefined later to forward", command: "apply_patch() { :; }\napply_patch() { exec apply_patch; }\n" + patch, loader: true},
		{name: "program through command", command: "apply_patch() { :; }\ncommand " + patch},
		{name: "program through env", command: "apply_patch() { :; }\nenv " + patch},
		{name: "function that forwards to the program", command: "apply_patch() { exec apply_patch; }\n" + patch, loader: true},
		{name: "function that forwards by path", command: "apply_patch() { /usr/bin/apply_patch; }\n" + patch, loader: true},
		{name: "function that forwards through command, unread as without the function", command: "apply_patch() { command apply_patch; }\n" + patch},
		{name: "function with a patch of its own", command: "apply_patch() { :; }\n" + patch + patch, loader: false},
		{name: "function body prints the program name", command: "apply_patch() { printf 'apply_patch notes' > notes.txt; }\n" + patch},
		{name: "function body echoes the word unset", command: "apply_patch() { echo unset; }\n" + patch},
		{name: "function body touches a file named after the program", command: "apply_patch() { touch apply_patch_notes.txt; }\n" + patch},
		{name: "builtin with the word unset after the call", command: "apply_patch() { :; }\n" + patch + ": unset\n"},
		{name: "program name printed after the call", command: "apply_patch() { :; }\n" + patch + "printf apply_patch > notes.txt\n"},
		{name: "unset of a variable after the call", command: "apply_patch() { :; }\n" + patch + "unset TMPFILE\n"},
		{name: "unset of the function after the call", command: "apply_patch() { :; }\n" + patch + "unset -f apply_patch\n"},
		{name: "unset of another function before the call", command: "apply_patch() { :; }\nunset -f other\n" + patch},
		{name: "unset of the function in a loop around the call", command: "apply_patch() { :; }\nfor i in 1 2; do\n" + patch + "unset -f apply_patch\ndone\n", loader: true},
		{name: "unset of the function through command", command: "apply_patch() { :; }\ncommand unset -f apply_patch\n" + patch, loader: true},
		{name: "unset of a name that is not literal", command: "apply_patch() { :; }\nunset -f apply_patc?\n" + patch, loader: true},
		{name: "unset of the function in an assignment of the call", command: "apply_patch() { :; }\nX=\"$(unset -f apply_patch)\" " + patch, loader: true},
		{name: "function that forwards through another function", command: "apply_patch() { helper; }\nhelper() { exec apply_patch; }\n" + patch, loader: true},
		{name: "program run by a wrapper before the call", command: "apply_patch() { :; }\nenv apply_patch --help\n" + patch},
		{name: "builtin shadowed by a harmless function before the call", command: "apply_patch() { :; }\nprintf() { :; }\nprintf apply_patch\n" + patch},
		{name: "baseline command wrapper", command: "command " + patch},
		{name: "baseline env wrapper", command: "env " + patch},
		{name: "other function does not hide the program", command: "other() { :; }\n" + patch, loader: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "exec_command", Command: row.command, CWD: "/tmp"}
			facts := Analyze(input)
			loader := ExactGlobalLDPreloadFileWrite(input, facts)
			for _, simple := range SimpleCommands(input, facts) {
				child := Input{Tool: "exec_command", Command: simple.Text, CWD: simple.CWD, ShellFunctionCall: simple.FunctionCall}
				loader = loader || ExactGlobalLDPreloadFileWrite(child, Analyze(child))
			}
			if loader != row.loader {
				t.Fatalf("a child command reads the loader patch = %t, want %t", loader, row.loader)
			}
		})
	}
}
