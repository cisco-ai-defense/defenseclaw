// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// Every rule is evaluated on each simple command with the same facts and
// disposition it gets when that command is submitted by itself.
func TestTrustedActionEverySimpleCommandMatchesStandalone(t *testing.T) {
	const connector = "all-simple-commands-test"
	installDefaultProfileConnector(t, connector)
	tests := []struct {
		name, command, alone, ruleID, cwd, aloneCWD string
	}{
		{"sequence", "cat ~/.ssh/id_rsa; echo done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"and list", "true && cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"or list", "false || cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"pipeline", "cat ~/.ssh/id_rsa | cat", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"group", "{ cat ~/.ssh/id_rsa; }", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"subshell", "(cat ~/.ssh/id_rsa)", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"redirected group", "{ cat ~/.ssh/id_rsa; } 2>/tmp/error", "cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"credential input on group", "{ cat; } < /home/alice/.ssh/id_rsa", "cat < /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"subshell in pipeline", "(cat ~/.ssh/id_rsa) | cat", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"negated", "! cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"background", "cat ~/.ssh/id_rsa & echo done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"if body", "if true; then cat ~/.ssh/id_rsa; fi", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"if body changes later directory", "if true; then cd /home/alice; fi; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/repo", "/home/alice"},
		{"loop body changes later directory", "for i in 1; do cd /home/alice; done; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/repo", "/home/alice"},
		{"while body", "while true; do cat ~/.ssh/id_rsa; done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"for body", "for i in 1; do cat ~/.ssh/id_rsa; done", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"case body", "case x in x) cat ~/.ssh/id_rsa;; esac", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"env prefix", "X=1 cat ~/.ssh/id_rsa; echo done", "X=1 cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"env prefix under redirected group", "{ X=1 cat ~/.ssh/id_rsa; } 2>/tmp/error", "X=1 cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"own redirect", "cat ~/.ssh/id_rsa 2>/tmp/error; echo done", "cat ~/.ssh/id_rsa 2>/tmp/error", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"bare assignment", "X=1; cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"resolution assignment", "PATH=/tmp; cat ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"home assignment retains identity", "HOME=/tmp; cat /home/alice/.ssh/id_rsa", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"static cd", "cd /home/alice && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"failed cd keeps old directory", "cd /does/not/exist/defenseclaw; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice", ""},
		{"cd back", "cd /tmp; cd -; cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice", ""},
		{"home cd", "cd \"$HOME\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"tilde cd", "cd ~ && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"assigned cd", "DIR=/home/alice; cd \"$DIR\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"pwd cd", "cd \"$PWD/..\" && cat .ssh/id_rsa", "cat .ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", "/home/alice"},
		{"pwd after cd", "cd /home/alice && cat \"$PWD/.ssh/id_rsa\"", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"assigned path", "KEY=/home/alice/.ssh/id_rsa; cat \"$KEY\"", "cat /home/alice/.ssh/id_rsa", "PATH-SSH-KEY", "/home/alice/project", ""},
		{"sqlite sequence", "sqlite3 app.db '.shell /bin/sh'; echo done", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite and list", "true && sqlite3 app.db '.shell /bin/sh'", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite pipeline", "sqlite3 app.db '.shell /bin/sh' | cat", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite subshell", "(sqlite3 app.db '.shell /bin/sh')", "sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite redirected group", "{ sqlite3 app.db '.shell /bin/sh'; } 2>/tmp/error", "sqlite3 app.db '.shell /bin/sh' 2>/tmp/error", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"sqlite env prefix", "X=1 sqlite3 app.db '.shell /bin/sh'; true", "X=1 sqlite3 app.db '.shell /bin/sh'", "exec.sqlite_client_shell_escape", "/repo", ""},
		{"mysql or list", "mysql --database=app --execute='\\! /bin/bash' || true", "mysql --database=app --execute='\\! /bin/bash'", "exec.mysql_client_shell_escape", "/repo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := func(command, cwd string) *RuleFinding {
				request := trustedActionRequest{
					Input: actionfacts.Input{Tool: "shell", Command: command, CWD: cwd,
						ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
					LegacyText: command, Connector: connector, EnforcementCapable: true,
				}
				return findingWithID(dispatchTrustedAction(t.Context(), request), tt.ruleID)
			}
			aloneCWD := tt.aloneCWD
			if aloneCWD == "" {
				aloneCWD = tt.cwd
			}
			alone := check(tt.alone, aloneCWD)
			got := check(tt.command, tt.cwd)
			if alone == nil {
				t.Fatalf("%s: standalone rule did not match", tt.ruleID)
			}
			if got == nil || got.contributesToEnforcement() != alone.contributesToEnforcement() ||
				got.contributesToAlertOnly() != alone.contributesToAlertOnly() {
				t.Errorf("%q: %s finding=%+v, standalone=%+v", tt.command, tt.ruleID, got, alone)
			}
		})
	}
}

// GAP-0789: an unrelated command before or after a read cannot remove the
// read-path rule's standalone disposition. Some reads are advisory by policy;
// those must keep the same disposition as the standalone read too.
func TestTrustedActionReadPathsInEveryListPosition(t *testing.T) {
	const connector = "read-path-list-position-test"
	installDefaultProfileConnector(t, connector)
	reads := []struct {
		name, ruleID, command string
		noStandaloneFinding   bool
	}{
		{name: "SSH private key", ruleID: "PATH-SSH-KEY", command: "cat /home/alice/.ssh/id_rsa"},
		{name: "AWS credentials", ruleID: "PATH-AWS-CREDS", command: "cat /home/alice/.aws/credentials"},
		{name: "AWS config", ruleID: "PATH-AWS-CONFIG", command: "cat /home/alice/.aws/config"},
		{name: "password-cracker potfile", ruleID: "PATH-PASSWORD-CRACKER-POTFILE", command: "cat /home/alice/.john/john.pot"},
		{name: "Kubernetes config", ruleID: "PATH-KUBE", command: "cat /home/alice/.kube/config"},
		{name: "Docker config", ruleID: "PATH-DOCKER", command: "cat /home/alice/.docker/config.json"},
		{name: "GnuPG keyring", ruleID: "PATH-GNUPG", command: "cat /home/alice/.gnupg/secring.gpg"},
		{name: "npmrc alias", ruleID: "PATH-DOCKER", command: "cat /home/alice/.npmrc"},
		{name: "pypirc alias", ruleID: "PATH-DOCKER", command: "cat /home/alice/.pypirc"},
		{name: "Git credentials", ruleID: "PATH-GIT-CREDS", command: "cat /home/alice/.git-credentials"},
		{name: "netrc alias", ruleID: "PATH-GIT-CREDS", command: "cat /home/alice/.netrc"},
		{name: "environment file", ruleID: "PATH-ENV-FILE", command: "cat /home/alice/project/.env", noStandaloneFinding: true},
		{name: "passwd", ruleID: "PATH-ETC-PASSWD", command: "cat /etc/passwd", noStandaloneFinding: true},
		{name: "sudoers", ruleID: "PATH-ETC-SUDOERS", command: "cat /etc/sudoers", noStandaloneFinding: true},
		{name: "shadow", ruleID: "PATH-ETC-SHADOW", command: "cat /etc/shadow"},
		{name: "proc environ", ruleID: "PATH-PROC-ENVIRON", command: "cat /proc/self/environ"},
		{name: "cloud credentials", ruleID: "secrets.cloud_credential_read", command: "cat /home/alice/.config/gcloud/application_default_credentials.json"},
		{name: "browser sessions", ruleID: "secrets.browser_session_store_read", command: "cat '/home/alice/.config/google-chrome/Default/Login Data'"},
		{name: "workload token", ruleID: "secrets.workload_identity_token_read", command: "cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
	}
	forms := []struct {
		name, first, last, middle string
	}{
		{"sequence", "%s; true", "true; %s", "true; %s; true"},
		{"and list", "%s && true", "true && %s", "true && %s && true"},
		{"or list", "%s || true", "false || %s", "false || %s || true"},
		{"pipeline", "%s | cat", "true | %s", "true | %s | cat"},
		{"newline", "%s\ntrue", "true\n%s", "true\n%s\ntrue"},
	}
	check := func(command string) []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
	}
	for _, read := range reads {
		t.Run(read.name, func(t *testing.T) {
			aloneFindings := check(read.command)
			alone := findingWithID(aloneFindings, read.ruleID)
			if (alone == nil) != read.noStandaloneFinding {
				t.Fatalf("%s: standalone %s finding=%+v, all=%v", read.command, read.ruleID,
					alone, FindingStrings(aloneFindings))
			}
			for _, form := range forms {
				for position, format := range map[string]string{
					"first": form.first, "last": form.last, "middle": form.middle,
				} {
					t.Run(form.name+"/"+position, func(t *testing.T) {
						command := fmt.Sprintf(format, read.command)
						got := findingWithID(check(command), read.ruleID)
						if (got == nil) != (alone == nil) || got != nil &&
							(got.contributesToEnforcement() != alone.contributesToEnforcement() ||
								got.contributesToAlertOnly() != alone.contributesToAlertOnly()) {
							t.Errorf("%q: %s finding=%+v, standalone=%+v", command, read.ruleID, got, alone)
						}
					})
				}
			}
		})
	}
}

func TestTrustedActionResolutionPrefixMatchesStandaloneInList(t *testing.T) {
	const connector = "compound-resolution-prefix-test"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	// A PATH prefix can only pick another rm, so the call is also judged
	// without it (GAP-1200): in a list it gets the finding it gets alone.
	standalone := "PATH=/definitely/missing $'rm' -rf /"
	dispatch := func(command string) *RuleFinding {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: "/repo",
				DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		return findingWithID(findings, "CMD-RM-RF")
	}
	alone := dispatch(standalone)
	if alone == nil {
		t.Fatalf("%q: no CMD-RM-RF finding", standalone)
	}
	for _, command := range []string{
		standalone + "; true",
		"true && " + standalone,
		"false || " + standalone,
	} {
		if finding := dispatch(command); finding == nil ||
			finding.contributesToEnforcement() != alone.contributesToEnforcement() {
			t.Errorf("%q: CMD-RM-RF finding=%+v, standalone=%+v", command, finding, *alone)
		}
	}
}

func TestTrustedActionCompoundEvaluationLimitBlocks(t *testing.T) {
	const connector = "compound-limit-test"
	installDefaultProfileConnector(t, connector)
	command := strings.Repeat("true; ", 128) + "rm -rf /"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	limit := findingWithID(findings, "ACTION-COMPOUND-LIMIT")
	if limit == nil || !limit.contributesToEnforcement() ||
		buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
		t.Fatalf("over-limit action was not blocked: %v", FindingStrings(findings))
	}
}

func TestTrustedActionRecursiveFunctionParseGapDoesNotRefuse(t *testing.T) {
	const connector = "compound-recursion-test"
	installDefaultProfileConnector(t, connector)
	command := "f() { f; }; f"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	if finding := findingWithID(findings, "ACTION-COMPOUND-UNPROVEN"); finding != nil ||
		buildVerdict(findings, "tool_call").Action == guardrailActionBlock {
		t.Fatalf("recursive function parse gap refused a benign action: %v", FindingStrings(findings))
	}
}

func TestTrustedActionFunctionCallSpellingsMatchBody(t *testing.T) {
	const connector = "compound-function-spellings-test"
	installDefaultProfileConnector(t, connector)
	for _, command := range []string{
		"f() { rm -rf /; }; 'f'",
		`f() { rm -rf /; }; "f"; true`,
		`f() { rm -rf /; }; \f`,
		"f() { rm -rf /; }; command f",
		"f() { rm -rf /; }; builtin f",
		"f() { rm -rf /; }; time f",
		"f() { rm -rf /; }; eval f",
		"f() { rm -rf /; }; trap f EXIT",
	} {
		t.Run(command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: command, Connector: connector, EnforcementCapable: true,
			})
			if buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
				t.Errorf("function call was not blocked: %v", FindingStrings(findings))
			}
		})
	}
	// $x names no function the walk can read (x comes from the
	// environment): no refusal for parse uncertainty. x=f; $x calls f and
	// is judged by its body (GAP-0934).
	command := "f() { rm -rf /; }; $x"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	if got := findingWithID(findings, "ACTION-COMPOUND-UNPROVEN"); got != nil ||
		buildVerdict(findings, "tool_call").Action == guardrailActionBlock {
		t.Errorf("unresolved function call was refused by parse uncertainty: %v", FindingStrings(findings))
	}
	command = "f() { rm -rf /; }; x=f; $x"
	findings = dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	if got := findingWithID(findings, "CMD-RM-RF"); got == nil || !got.contributesToEnforcement() ||
		findingWithID(findings, "ACTION-COMPOUND-UNPROVEN") != nil {
		t.Errorf("assignment-bound function call was not judged by its body: %v", FindingStrings(findings))
	}
	for _, command := range []string{
		"f() { cat ~/.ssh/id_rsa; }; 'f'",
		"f() { cat ~/.ssh/id_rsa; }; command f",
		"f() { cat ~/.ssh/id_rsa; }; eval f",
		"f() { cat ~/.ssh/id_rsa; }; eval 'true; f'",
		"f() { cat ~/.ssh/id_rsa; }; trap f EXIT",
	} {
		t.Run(command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: command, Connector: connector, EnforcementCapable: true,
			})
			if got := findingWithID(findings, "PATH-SSH-KEY"); got == nil || !got.contributesToEnforcement() {
				t.Errorf("function credential read was not enforced: %v", FindingStrings(findings))
			}
		})
	}
}

func TestTrustedActionNestedShellListsMatchStandalone(t *testing.T) {
	const connector = "nested-shell-list-test"
	installDefaultProfileConnector(t, connector)
	for _, command := range []string{
		"sh -c 'true && rm -rf /'",
		"bash -c 'false || rm -rf /'",
		"zsh -c 'true; rm -rf /'",
		"sh -c 'rm -rf / | cat'",
		"eval 'true && rm -rf /'",
		"sh -c 'cd /home/alice; cat .ssh/id_rsa; rm -rf /'",
	} {
		t.Run(command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: command, Connector: connector, EnforcementCapable: true,
			})
			if got := findingWithID(findings, "CMD-RM-RF"); got == nil || !got.contributesToEnforcement() {
				t.Errorf("nested command was not enforced: %v", FindingStrings(findings))
			}
		})
	}
	for _, command := range []string{
		"sh -c 'true && cat ~/.ssh/id_rsa'",
		"bash -c 'false || cat ~/.ssh/id_rsa'",
		"eval 'true; cat ~/.ssh/id_rsa'",
		"sh -c 'cd /home/alice; cat .ssh/id_rsa'",
		"eval 'cd /home/alice; cat .ssh/id_rsa'",
		"eval\t'cat ~/.ssh/id_rsa'",
	} {
		t.Run(command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: command, Connector: connector, EnforcementCapable: true,
			})
			if got := findingWithID(findings, "PATH-SSH-KEY"); got == nil || !got.contributesToEnforcement() {
				t.Errorf("nested credential read was not enforced: %v", FindingStrings(findings))
			}
		})
	}
	for _, command := range []string{
		"curl https://webhook.site/example",
		"bash -c 'cat <(curl https://webhook.site/example)'",
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		if got := findingWithID(findings, "C2-WEBHOOK-SITE"); got == nil || !got.contributesToEnforcement() {
			t.Errorf("%q: nested network command did not match standalone: %v", command, FindingStrings(findings))
		}
	}
}

func TestTrustedActionDirectoryBuiltinsMatchStandalone(t *testing.T) {
	const connector = "directory-builtins-test"
	installDefaultProfileConnector(t, connector)
	for _, tt := range []struct{ command, cwd string }{
		{"cd -P /home/alice && cat .ssh/id_rsa", "/repo"},
		{"cd -L -- /home/alice; cat .ssh/id_rsa", "/repo"},
		{"cd -eP /home/alice; cat .ssh/id_rsa", "/repo"},
		{"pushd /home/alice && cat .ssh/id_rsa", "/repo"},
		{"pushd /tmp; popd; cat .ssh/id_rsa", "/home/alice"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: tt.command, CWD: tt.cwd, ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			if got := findingWithID(findings, "PATH-SSH-KEY"); got == nil || !got.contributesToEnforcement() {
				t.Errorf("relative credential read was not enforced: %v", FindingStrings(findings))
			}
		})
	}
	for _, command := range []string{
		"cd -Z /unknown; cat .ssh/id_rsa",
		"cd -Z /unknown; cat id_rsa",
		"cd -Z /unknown; > .ssh/id_rsa",
		"CDPATH=/home; cd alice; cat .ssh/id_rsa",
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		if got := findingWithID(findings, "ACTION-COMPOUND-UNPROVEN"); got != nil ||
			buildVerdict(findings, "tool_call").Action == guardrailActionBlock {
			t.Errorf("%q: unknown directory was refused by parse uncertainty: %v", command, FindingStrings(findings))
		}
	}
}

func TestTrustedActionCStyleLoopBodyMatchesStandalone(t *testing.T) {
	const connector = "c-style-loop-test"
	installDefaultProfileConnector(t, connector)
	for _, tt := range []struct {
		command string
		block   bool
	}{
		{"for ((i=0;i<3;i++)); do echo $i; done", false},
		{"for ((i=0;i<3;i++)); do rm -rf /; done", true},
	} {
		t.Run(tt.command, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: tt.command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX},
				LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if blocked != tt.block {
				t.Errorf("block=%v, want %v: %v", blocked, tt.block, FindingStrings(findings))
			}
			if tt.block {
				if got := findingWithID(findings, "CMD-RM-RF"); got == nil || !got.contributesToEnforcement() {
					t.Errorf("loop body not enforced: %v", FindingStrings(findings))
				}
			}
		})
	}
}

func TestTrustedActionWindowsCompoundMatchesStandalone(t *testing.T) {
	const connector = "windows-compound-test"
	installDefaultProfileConnector(t, connector)
	for _, tt := range []struct {
		name, command, alone string
		dialect              actionfacts.Dialect
	}{
		{"powershell semicolon", `Write-Output a; Remove-Item -Recurse -Force C:\`, `Remove-Item -Recurse -Force C:\`, actionfacts.DialectPowerShell},
		{"powershell pipeline", `Write-Output a | Remove-Item -Recurse -Force C:\`, `Remove-Item -Recurse -Force C:\`, actionfacts.DialectPowerShell},
		{"cmd ampersand", `echo a & rmdir /s /q C:\`, `rmdir /s /q C:\`, actionfacts.DialectCMD},
		{"cmd and", `echo a && rmdir /s /q C:\`, `rmdir /s /q C:\`, actionfacts.DialectCMD},
		{"cmd or", `echo a || rmdir /s /q C:\`, `rmdir /s /q C:\`, actionfacts.DialectCMD},
	} {
		t.Run(tt.name, func(t *testing.T) {
			check := func(command string) []RuleFinding {
				return dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:      actionfacts.Input{Tool: "shell", Command: command, CWD: `C:\repo`, DialectHint: tt.dialect},
					LegacyText: command, Connector: connector, EnforcementCapable: true,
				})
			}
			alone := findingWithID(check(tt.alone), "CMD-RM-RF")
			got := findingWithID(check(tt.command), "CMD-RM-RF")
			if alone == nil || !alone.contributesToEnforcement() {
				t.Fatal("standalone command did not enforce")
			}
			if got == nil || !got.contributesToEnforcement() {
				t.Errorf("compound command did not enforce: %+v", got)
			}
			tool := "powershell"
			if tt.dialect == actionfacts.DialectCMD {
				tool = "cmd"
			}
			args, err := json.Marshal(map[string]string{"command": tt.command})
			if err != nil {
				t.Fatal(err)
			}
			structured := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: tool, Args: args, CWD: `C:\repo`, DialectHint: tt.dialect},
				LegacyText: string(args), Connector: connector, EnforcementCapable: true,
			})
			if got := findingWithID(structured, "CMD-RM-RF"); got == nil || !got.contributesToEnforcement() {
				t.Errorf("structured compound command did not enforce: %v", FindingStrings(structured))
			}
		})
	}
}
