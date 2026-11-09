// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// The content proofs read the envelope of an apply_patch here-document whatever
// the spelling of its delimiter (<<EOF, <<"EOF", <<'EOF', <<\EOF, <<-EOF), as
// they read the apply_patch tool. A body the shell expands is read as the text
// it shows: a file the patch names must not hold an expansion, and a line with
// one is unknown content.
func TestContentProofsReadTheEnvelopeOfEveryHereDocumentSpelling(t *testing.T) {
	const lib = "/usr/local/lib/libreview.so"
	envelope := func(directives string) string {
		return "*** Begin Patch\n" + directives + "*** End Patch\n"
	}
	loader := "*** Add File: /etc/ld.so.preload\n+" + lib + "\n"
	pam := "*** Update File: /etc/pam.d/sshd\n@@\n+auth sufficient pam_permit.so\n"
	docker := "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n"
	sudoers := "*** Add File: /etc/sudoers.d/review\n+reviewer ALL=(ALL) NOPASSWD: ALL\n"
	spellings := []struct{ name, open, close, indent string }{
		{"single quoted", "<<\x27EOF\x27", "EOF", ""},
		{"unquoted", "<<EOF", "EOF", ""},
		{"double quoted", "<<\"EOF\"", "EOF", ""},
		{"backslash", "<<\\EOF", "EOF", ""},
		{"dash unquoted", "<<-EOF", "EOF", ""},
		{"dash unquoted with tabs", "<<-EOF", "\tEOF", "\t"},
		{"dash double quoted with tabs", "<<-\"EOF\"", "\t\tEOF", "\t\t"},
		{"dash single quoted with tabs", "<<-\x27EOF\x27", "\tEOF", "\t"},
		{"file descriptor 0", "0<<EOF", "EOF", ""},
	}
	form := func(open, close, indent, body string) string {
		if indent != "" {
			body = indent + strings.ReplaceAll(strings.TrimSuffix(body, "\n"), "\n", "\n"+indent) + "\n"
		}
		return "apply_patch " + open + "\n" + body + close + "\n"
	}
	type proofs struct{ loader, pam, docker, sudoers bool }
	bodies := []struct {
		name, body string
		want       proofs
	}{
		{"loader", envelope(loader), proofs{loader: true}},
		{"pam", envelope(pam), proofs{pam: true}},
		{"docker", envelope(docker), proofs{docker: true}},
		{"sudoers", envelope(sudoers), proofs{sudoers: true}},
		{"after an ordinary file", envelope("*** Add File: notes.txt\n+hello\n" + loader), proofs{loader: true}},
		{"ordinary file", envelope("*** Add File: notes.txt\n+hello\n"), proofs{}},
		{"ordinary profile fragment", envelope("*** Add File: /etc/profile.d/review.sh\n+export EDITOR=vi\n"), proofs{}},
		{"pam comment", envelope("*** Update File: /etc/pam.d/sshd\n@@\n+# reviewed by the team\n"), proofs{}},
		{"loopback registry", envelope("*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://127.0.0.1:5000\"]}\n"), proofs{}},
	}
	for _, spelling := range spellings {
		for _, body := range bodies {
			t.Run(spelling.name+"/"+body.name, func(t *testing.T) {
				for _, tool := range []string{"Bash", "exec_command"} {
					input := Input{Tool: tool, Command: form(spelling.open, spelling.close, spelling.indent, body.body), CWD: "/tmp"}
					facts := Analyze(input)
					_, pamProven := ExactPAMAuthenticationBypass(input, facts)
					got := proofs{
						ExactGlobalLDPreloadFileWrite(input, facts), pamProven,
						ExactDockerInsecureRegistryWrite(input, facts), ExactPOSIXUnrestrictedSudoersGrantWrite(facts),
					}
					if got != body.want {
						t.Fatalf("%s: loader, pam, docker, sudoers = %v, want %v", tool, got, body.want)
					}
				}
			})
		}
	}
}

// A body the shell expands is read as the text it shows. A protected file the
// text names with proven literal content is proven whatever else the body
// expands; a file directive that holds an expansion is no file the text names,
// and an expanded line is unknown content that proves nothing.
func TestContentProofsReadTheTextOfAnExpandingHereDocument(t *testing.T) {
	const lib = "/usr/local/lib/libreview.so"
	rows := []struct {
		name, body string
		loader     bool
	}{
		{"expansion in a comment line", "*** Add File: /etc/ld.so.preload\n+" + lib + "\n+# built by $USER\n", true},
		{"expansion in an ordinary file", "*** Add File: notes.txt\n+echo $HOME\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n", true},
		{"substitution in an ordinary file", "*** Add File: notes.txt\n+$(date)\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n", true},
		{"escaped dollar in an ordinary file", "*** Add File: notes.txt\n+cost \\$5\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n", true},
		{"library chosen by an expansion", "*** Add File: /etc/ld.so.preload\n+$LIBPATH\n", false},
		{"library chosen by a substitution", "*** Add File: /etc/ld.so.preload\n+$(printf %s " + lib + ")\n", false},
		{"directory chosen by an expansion", "*** Add File: $DIR/ld.so.preload\n+" + lib + "\n", false},
		{"directive with a backslash", "*** Add File: /etc/ld.so.pre\\load\n+" + lib + "\n", false},
		{"ordinary file with an expansion", "*** Add File: notes.txt\n+echo $HOME\n", false},
		{"ordinary file with a literal escape", "*** Add File: notes.txt\n+printf(\"a\\n\");\n", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "exec_command", Command: "apply_patch <<EOF\n*** Begin Patch\n" + row.body + "*** End Patch\nEOF\n", CWD: "/tmp"}
			if got := ExactGlobalLDPreloadFileWrite(input, Analyze(input)); got != row.loader {
				t.Fatalf("loader proof = %v, want %v", got, row.loader)
			}
		})
	}
}

// A delimiter or command the here-document reading does not model keeps the
// text unread: no proof from it.
func TestContentProofsReadNothingFromAnUnmodelledHereDocument(t *testing.T) {
	const body = "*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\n"
	for name, command := range map[string]string{
		"delimiter with an expansion": "apply_patch <<\"$X\"\n" + body + "$X\n",
		"stdin redirected first":      "apply_patch < other.patch <<EOF\n" + body + "EOF\n",
		"two here-documents":          "apply_patch <<A <<B\n" + body + "A\n" + body + "B\n",
		"extra argument":              "apply_patch --dry-run <<EOF\n" + body + "EOF\n",
		"cat is no patch program":     "cat <<EOF\n" + body + "EOF\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: command, CWD: "/tmp"}
			if ExactGlobalLDPreloadFileWrite(input, Analyze(input)) {
				t.Fatal("proof from an unmodelled here-document")
			}
		})
	}
}
