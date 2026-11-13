// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func nonShellReq(tool, args string, strict bool) trustedActionRequest {
	return trustedActionRequest{
		Input: actionfacts.Input{
			Tool: tool, Args: json.RawMessage(args), ActiveHome: "/home/u", CWD: "/home/u/work",
		},
		LegacyText:         args,
		Connector:          "claudecode",
		EnforcementCapable: true,
		StrictPolicy:       strict,
	}
}

func findingByID(findings []RuleFinding, id string) (RuleFinding, bool) {
	for _, f := range findings {
		if f.RuleID == id {
			return f, true
		}
	}
	return RuleFinding{}, false
}

func TestNonShellToolFindingsByEffect(t *testing.T) {
	cases := []struct {
		name, tool, args, rule string
	}{
		{"protected path via file tool", "mcp__filesystem__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"protected path in a batch", "mcp__bench__fs_read_batch", `{"paths":["/repo/a.md","/home/u/.aws/credentials"]}`, "PATH-AWS-CREDS"},
		{"protected path under an unknown key", "mcp__a__do_thing", `{"thing":"/home/u/.aws/credentials"}`, "PATH-AWS-CREDS"},
		{"credential store", "mcp__filesystem__read_file", `{"path":"/etc/k8s/admin.conf"}`, "PATH-K8S-CLUSTER-CRED"},
		{"destructive sql", "mcp__db__execute", `{"database":"ops","sql":"DROP TABLE t"}`, mcpSQLDestructiveRuleID},
		{"privilege sql", "mcp__db__execute", `{"database":"ops","sql":"UPDATE perms SET role='admin' WHERE d='a'"}`, mcpSQLPrivilegeRuleID},
		{"audit-off sql", "mcp__db__execute", `{"database":"ops","sql":"UPDATE audit_config SET enabled=false"}`, mcpSQLAuditOffRuleID},
		{"downgrade", "mcp__auth__reset_password", `{"user_id":1,"skip_2fa":true}`, mcpSettingDowngradeID},
		{"redirect off domain", "mcp__mail__send_batch", `{"recipients":["a@corp.example"],"bcc_override":"x@other.example"}`, mcpSendRedirectRuleID},
		{"decode and run", "mcp__code__execute", `{"code":"exec(base64.b64decode(s).decode())"}`, mcpCodeDecodeExecRuleID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(c.args, `"/`) {
				t.Skip("the case names a POSIX path; the Windows spelling is covered by the native file-tool tests")
			}
			got := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, false), nil)
			f, ok := findingByID(got, c.rule)
			if !ok {
				t.Fatalf("no %s in %+v", c.rule, got)
			}
			if f.enforcement != findingEnforcementAlertOnly {
				t.Fatalf("default tier: %s enforcement = %v, want alert-only (the role of an MCP effect is a guess)", c.rule, f.enforcement)
			}
			strict := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, true), nil)
			// Strict keeps the finding the rule gives (a path rule may itself be
			// alert-only, as for the AWS credentials file); it is never weaker
			// than the default tier's.
			if sf, ok := findingByID(strict, c.rule); !ok || sf.enforcement == findingEnforcementDetectionOnly {
				t.Fatalf("strict tier: %+v, want a visible finding", sf)
			}
		})
	}
}

func TestNonShellToolFindingsQuietCases(t *testing.T) {
	cases := []struct{ name, tool, args string }{
		{"unknown tool, no effects", "mcp__crm__lookup", `{"customer_id":"c-1"}`},
		{"ordinary read", "mcp__filesystem__read_file", `{"path":"/repo/README.md"}`},
		{"select", "mcp__db__query", `{"database":"ops","sql":"SELECT * FROM users WHERE id=1"}`},
		{"delete with where", "mcp__db__execute", `{"database":"ops","sql":"DELETE FROM s WHERE expires < now()"}`},
		{"setting kept on", "mcp__auth__configure", `{"skip_2fa":false,"verify_ssl":true}`},
		{"bcc to the same domain", "mcp__mail__send", `{"to":"a@corp.example","bcc":"b@corp.example"}`},
		{"bcc to loopback", "mcp__http__post", `{"url":"http://localhost:8080/x","forward_to":"http://127.0.0.1/y"}`},
		{"code that only decodes", "mcp__code__execute", `{"code":"import base64\nprint(base64.b64decode(s))"}`},
		{"a native tool is not read here", "Read", `{"file_path":"/home/u/.ssh/id_rsa"}`},
		{"a shell tool is not read here", "Bash", `{"command":"ls"}`},
		{"not a JSON object", "mcp__a__b", `[1,2]`},
		{"empty", "mcp__a__b", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, false), nil); len(got) != 0 {
				t.Fatalf("findings = %+v", got)
			}
		})
	}
}

func TestNonShellToolFindingsKeepEarlierFindings(t *testing.T) {
	prior := []RuleFinding{{RuleID: "X", Severity: "LOW"}}
	got := nonShellToolFindings(context.Background(), nonShellReq("mcp__db__execute", `{"database":"o","sql":"TRUNCATE t"}`, false), prior)
	if len(got) != 2 || got[0].RuleID != "X" {
		t.Fatalf("findings = %+v", got)
	}
	if len(prior) != 1 {
		t.Fatal("the input slice was changed")
	}
}

func TestNonShellToolFindingsNotCapableAddsNothing(t *testing.T) {
	req := nonShellReq("mcp__db__execute", `{"database":"o","sql":"TRUNCATE t"}`, false)
	req.EnforcementCapable = false
	if got := nonShellToolFindings(context.Background(), req, nil); len(got) != 0 {
		t.Fatalf("findings = %+v", got)
	}
}

func TestShellToolFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cases are POSIX shell commands on POSIX paths")
	}
	loud := map[string]string{
		"pulumi stack output --show-secrets --stack a/b/c --json": "CMD-SECRET-REVEAL",
		"op item get 'X' --reveal --format=json":                  "CMD-SECRET-REVEAL",
		"vault token lookup":                                      "CMD-SECRET-LOOKUP",
		"aws iam get-access-key":                                  "CMD-SECRET-LOOKUP",
		"git show HEAD:config/secrets.yaml":                       "CMD-GIT-SHOW-SECRET",
		"chmod u+s /tmp/x":                                        "CMD-PRIV-SETUID",
		"echo '0 3 * * * root /x' | sudo tee /etc/cron.d/x":       "CMD-PERSIST-SYSTEM-SCHEDULE",
		"cat /home/u/.vault-token":                                "PATH-CRED-STORE-USER",
	}
	for command, rule := range loud {
		args, _ := json.Marshal(map[string]string{"command": command})
		req := nonShellReq("Bash", string(args), false)
		got := shellToolFindings(context.Background(), req, nil)
		f, ok := findingByID(got, rule)
		if !ok || f.enforcement != findingEnforcementAlertOnly {
			t.Errorf("%q: %s missing or not alert-only in %+v", command, rule, got)
		}
		strict := shellToolFindings(context.Background(), nonShellReq("Bash", string(args), true), nil)
		if sf, ok := findingByID(strict, rule); !ok || sf.enforcement == findingEnforcementAlertOnly {
			t.Errorf("%q strict: %+v", command, sf)
		}
	}
	quiet := []string{
		"ls -la", "chmod 644 /tmp/x", "chmod +x run.sh", "vault status", "aws s3 ls",
		"git show main:stack/scripts/tool_gating.env.sh", "git show HEAD:README.md",
		"cat /etc/passwd", "cp a.txt /etc/hosts", "echo hi > /tmp/x",
	}
	for _, command := range quiet {
		args, _ := json.Marshal(map[string]string{"command": command})
		if got := shellToolFindings(context.Background(), nonShellReq("Bash", string(args), false), nil); len(got) != 0 {
			t.Errorf("%q: findings = %+v", command, got)
		}
	}
}
