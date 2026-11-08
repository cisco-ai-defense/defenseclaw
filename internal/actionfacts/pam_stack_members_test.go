// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"strings"
	"testing"
)

const pamPermitAll = "auth       sufficient   pam_permit.so"

// stockPAMFiles are the stock PAM services an administrator edits: sshd and
// sudo of RHEL 9, Ubuntu and macOS. Their lines are the ordinary members of a
// stack: module lines, include and substack controls, @include directives, a
// leading "-" on a type, bracketed controls with run-on blanks and inline
// comments.
var stockPAMFiles = []struct{ name, target, text string }{
	{"rhel9 sshd", "/etc/pam.d/sshd", `#%PAM-1.0
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      password-auth
session    include      postlogin
# Used with polkit to reauthorize users in remote sessions
-session   optional     pam_reauthorize.so prepare
`},
	{"rhel9 sudo", "/etc/pam.d/sudo", `#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
`},
	{"ubuntu sshd", "/etc/pam.d/sshd", `# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so

# Standard Un*x authorization.
@include common-account

# SELinux needs to be the first session rule.
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close

# Set the loginuid process attribute.
session    required     pam_loginuid.so

# Standard Un*x session setup and teardown.
@include common-session

# Print the status of the user's mailbox upon successful login.
session    optional     pam_mail.so standard noenv # [1]

# Set up user limits from /etc/security/limits.conf.
session    required     pam_limits.so

session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale

session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open

# Standard Un*x password updating.
@include common-password
`},
	{"ubuntu sudo", "/etc/pam.d/sudo", `#%PAM-1.0
session required pam_env.so readenv=1 user_readenv=0
session required pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
`},
	{"macos sshd", "/etc/pam.d/sshd", `# sshd: auth account password session
auth       optional       pam_krb5.so use_kcminit
auth       optional       pam_ntlm.so try_first_pass
auth       optional       pam_mount.so try_first_pass
auth       required       pam_opendirectory.so try_first_pass
account    required       pam_nologin.so
account    required       pam_sacl.so sacl_service=ssh
account    required       pam_opendirectory.so
password   required       pam_opendirectory.so
session    required       pam_launchd.so
session    optional       pam_mount.so
`},
	{"macos sudo", "/etc/pam.d/sudo", `# sudo: auth account password session
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
`},
}

func pamEditOf(t *testing.T, target, oldText, newText string, extra ...any) Input {
	t.Helper()
	args := map[string]any{"file_path": target, "old_string": oldText, "new_string": newText}
	if len(extra) == 2 {
		args[extra[0].(string)] = extra[1]
	}
	return pamBypassInput(t, "Edit", args)
}

// TestPAMPermitAllIsProvenBesideAnyMemberOfTheStack pins that a permit-all auth
// line put anywhere in a stock service file is proven, however many include,
// substack and @include lines or lines with a trailing comment sit beside it,
// for an edit before or after any line and for a whole-file write.
func TestPAMPermitAllIsProvenBesideAnyMemberOfTheStack(t *testing.T) {
	for _, file := range stockPAMFiles {
		lines := strings.Split(strings.TrimSuffix(file.text, "\n"), "\n")
		for index, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			for _, row := range []struct{ name, oldText, newText string }{
				{"before", line, pamPermitAll + "\n" + line},
				{"after", line, line + "\n" + pamPermitAll},
			} {
				t.Run(file.name+"/edit "+row.name+" line "+strconv.Itoa(index), func(t *testing.T) {
					for _, replaceAll := range []any{nil, true, false} {
						input := pamEditOf(t, file.target, row.oldText, row.newText)
						if replaceAll != nil {
							input = pamEditOf(t, file.target, row.oldText, row.newText, "replace_all", replaceAll)
						}
						if _, proven := exactPAMOfCall(input); !proven {
							t.Fatalf("permit-all %s %q is not proven (replace_all=%v)", row.name, line, replaceAll)
						}
					}
				})
			}
			t.Run(file.name+"/write with the permit line before line "+strconv.Itoa(index), func(t *testing.T) {
				withPermit := append(append(append([]string{}, lines[:index]...), pamPermitAll), lines[index:]...)
				proof, proven := exactPAMOfCall(pamWriteInput(t, file.target, strings.Join(withPermit, "\n")+"\n"))
				if !proven || proof != PAMAuthenticationBypassFullReplacement {
					t.Fatalf("whole-file write with a permit-all line = %q, %t", proof, proven)
				}
			})
		}
		t.Run(file.name+"/stock file is not a bypass", func(t *testing.T) {
			if proof, proven := exactPAMOfCall(pamWriteInput(t, file.target, file.text)); proven {
				t.Fatalf("the stock file minted a %q proof", proof)
			}
		})
	}
}

// TestPAMPermitAllShapesAroundTheStackAreProven covers the other spellings of
// the same permit-all line and of the lines around it.
func TestPAMPermitAllShapesAroundTheStackAreProven(t *testing.T) {
	for _, row := range []struct{ name, text string }{
		{"substack beside", pamPermitAll + "\nauth       substack     password-auth\n"},
		{"include beside", pamPermitAll + "\nauth       include      postlogin\n"},
		{"at-include beside", "@include common-auth\n" + pamPermitAll + "\n"},
		{"inline comment", "auth sufficient pam_permit.so # example\n"},
		{"ignore-missing type", "-auth sufficient pam_permit.so\n"},
		{"bracket control", "auth [success=done default=ignore] pam_permit.so\n"},
		{"module path", "auth sufficient /usr/lib64/security/pam_permit.so\n"},
		{"continued line", "auth sufficient \\\npam_permit.so\n"},
		{"include after", "auth sufficient pam_permit.so\n@include common-auth\n"},
		{"line outside the grammar beside", "auth required pam_unix.so \"quoted\"\nauth sufficient pam_permit.so\n"},
		{"opaque line carrying the permit", "auth sufficient pam_permit.so \"quoted\"\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, proven := exactPAMOfCall(pamWriteInput(t, "/etc/pam.d/sshd", row.text)); !proven {
				t.Fatalf("%q is not proven", row.text)
			}
		})
	}
	t.Run("pam.conf with an include beside", func(t *testing.T) {
		text := "sshd auth include system-auth\nsshd auth sufficient pam_permit.so\n"
		if _, proven := exactPAMOfCall(pamWriteInput(t, "/etc/pam.conf", text)); !proven {
			t.Fatal("pam.conf permit-all beside an include is not proven")
		}
	})
}

// TestPAMOrdinaryEditsBesideTheStackAreNotProven is the benign twin: edits of
// the same files that add no permit-all auth line stay unproven.
func TestPAMOrdinaryEditsBesideTheStackAreNotProven(t *testing.T) {
	for _, file := range stockPAMFiles {
		lines := strings.Split(strings.TrimSuffix(file.text, "\n"), "\n")
		for index, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			for _, added := range []string{
				"# reviewed",
				"auth       required     pam_faillock.so preauth",
				"session    required     pam_limits.so",
				"account    required     pam_permit.so",
				"session    required     pam_permit.so",
				"auth       include      password-auth",
				"auth       substack     pam_permit.so",
				"@include common-auth",
			} {
				t.Run(file.name+"/"+added+" near line "+strconv.Itoa(index), func(t *testing.T) {
					input := pamEditOf(t, file.target, line, added+"\n"+line)
					if proof, proven := exactPAMOfCall(input); proven {
						t.Fatalf("ordinary edit minted a %q proof", proof)
					}
				})
			}
		}
	}
	t.Run("an edit that keeps a permit-all line the file already had", func(t *testing.T) {
		line := "auth required pam_permit.so"
		if _, proven := exactPAMOfCall(pamEditOf(t, "/etc/pam.d/sshd", line, line+"\n# kept")); proven {
			t.Fatal("kept line minted a proof")
		}
	})
	t.Run("a comment-only old text is a valid old text", func(t *testing.T) {
		if _, proven := exactPAMOfCall(pamEditOf(t, "/etc/pam.d/sshd", "#%PAM-1.0", "#%PAM-1.0\n"+pamPermitAll)); !proven {
			t.Fatal("permit-all after the header comment is not proven")
		}
	})
}
