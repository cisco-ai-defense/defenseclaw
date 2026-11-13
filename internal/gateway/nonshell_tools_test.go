// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"

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
		{"protected path via file tool", "mcp__acme__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"protected path in a batch", "mcp__bench__fs_read_batch", `{"paths":["/repo/a.md","/home/u/.aws/credentials"]}`, "PATH-AWS-CREDS"},
		{"protected path under an unknown key", "mcp__a__do_thing", `{"thing":"/home/u/.aws/credentials"}`, "PATH-AWS-CREDS"},
		{"credential store", "mcp__acme__read_file", `{"path":"/etc/k8s/admin.conf"}`, "PATH-K8S-CLUSTER-CRED"},
		{"destructive sql", "mcp__db__execute", `{"database":"ops","sql":"DROP TABLE t"}`, mcpSQLDestructiveRuleID},
		{"privilege sql", "mcp__db__execute", `{"database":"ops","sql":"UPDATE perms SET role='admin' WHERE d='a'"}`, mcpSQLPrivilegeRuleID},
		{"audit-off sql", "mcp__db__execute", `{"database":"ops","sql":"UPDATE audit_config SET enabled=false"}`, mcpSQLAuditOffRuleID},
		{"downgrade", "mcp__auth__reset_password", `{"user_id":1,"skip_2fa":true}`, mcpSettingDowngradeID},
		{"redirect off domain", "mcp__mail__send_batch", `{"from":"me@corp.example","recipients":["a@corp.example"],"bcc_override":"x@other.example"}`, mcpSendRedirectRuleID},
		{"decode and run", "mcp__code__execute", `{"code":"exec(base64.b64decode(s).decode())"}`, mcpCodeDecodeExecRuleID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(c.args, `"/`) {
				t.Skip("the case names a POSIX path; the Windows spelling is covered by the native file-tool tests")
			}
			got := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, false), nil, "")
			f, ok := findingByID(got, c.rule)
			if !ok {
				t.Fatalf("no %s in %+v", c.rule, got)
			}
			if f.enforcement != findingEnforcementAlertOnly {
				t.Fatalf("default tier: %s enforcement = %v, want alert-only (the role of an MCP effect is a guess)", c.rule, f.enforcement)
			}
			strict := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, true), nil, "")
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
		{"bcc to loopback", "mcp__http__post", `{"url":"http://localhost:8080/x","forward_to":"http://127.0.0.1/y"}`},
		{"code that only decodes", "mcp__code__execute", `{"code":"import base64\nprint(base64.b64decode(s))"}`},
		{"a native tool is not read here", "Read", `{"file_path":"/home/u/.ssh/id_rsa"}`},
		{"a shell tool is not read here", "Bash", `{"command":"ls"}`},
		{"not a JSON object", "mcp__a__b", `[1,2]`},
		{"empty", "mcp__a__b", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nonShellToolFindings(context.Background(), nonShellReq(c.tool, c.args, false), nil, ""); len(got) != 0 {
				t.Fatalf("findings = %+v", got)
			}
		})
	}
}

func TestNonShellToolFindingsKeepEarlierFindings(t *testing.T) {
	prior := []RuleFinding{{RuleID: "X", Severity: "LOW"}}
	got := nonShellToolFindings(context.Background(), nonShellReq("mcp__db__execute", `{"database":"o","sql":"TRUNCATE t"}`, false), prior, "")
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
	if got := nonShellToolFindings(context.Background(), req, nil, ""); len(got) != 0 {
		t.Fatalf("findings = %+v", got)
	}
}

func TestShellToolFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cases are POSIX shell commands on POSIX paths")
	}
	loud := map[string]string{
		"pulumi stack output --show-secrets --stack a/b/c --json":     "CMD-SECRET-REVEAL",
		"op item get 'X' --reveal --format=json":                      "CMD-SECRET-REVEAL",
		"vault token lookup":                                          "CMD-SECRET-LOOKUP",
		"aws iam get-access-key":                                      "CMD-SECRET-LOOKUP",
		"git show HEAD:config/secrets.yaml":                           "CMD-GIT-SHOW-SECRET",
		"chmod u+s /tmp/x":                                            "CMD-PRIV-SETUID",
		"PATH=/tmp/badpath:$PATH pkexec true":                         "CMD-PRIV-PATH-HIJACK",
		"echo '0 3 * * * root /home/u/x.sh' | sudo tee /etc/cron.d/x": "CMD-PERSIST-SYSTEM-SCHEDULE",
		"cat /home/u/.vault-token":                                    "PATH-CRED-STORE-USER",
		"echo 'svc:x:0:0::/:/bin/sh' | sudo tee -a /etc/passwd":       "PATH-ETC-PASSWD",
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
		"git show main:stack/scripts/tool_gating.env.sh", "git show HEAD:README.md", "git show HEAD:internal/gateway/user_scoped_credentials.go",
		"cat /run/secrets/redis_auth", "PATH=/usr/local/bin:$PATH make test", "PATH=/tmp/x:$PATH ls", "echo 'git:x:1000:1000::/home/git:/bin/bash' >> /etc/passwd",
		"echo '@reboot root /opt/app/worker.py' > /etc/cron.d/worker",
		"cat /etc/passwd", "cp a.txt /etc/hosts", "echo hi > /tmp/x",
	}
	for _, command := range quiet {
		args, _ := json.Marshal(map[string]string{"command": command})
		if got := shellToolFindings(context.Background(), nonShellReq("Bash", string(args), false), nil); len(got) != 0 {
			t.Errorf("%q: findings = %+v", command, got)
		}
	}
}

func TestNonShellToolFindingsBoundsAreNeverClean(t *testing.T) {
	// A protected path after many filler paths is still judged.
	var paths []string
	for i := 0; i < 40; i++ {
		paths = append(paths, fmt.Sprintf("/repo/docs/f%02d.md", i))
	}
	paths = append(paths, "/home/u/.ssh/id_rsa")
	b, _ := json.Marshal(map[string]any{"paths": paths})
	got := nonShellToolFindings(context.Background(), nonShellReq("mcp__filesystem__read_multiple_files", string(b), false), nil, "")
	if _, ok := findingByID(got, "PATH-SSH-KEY"); !ok {
		t.Fatalf("a protected path after 40 filler paths evaded: %+v", got)
	}
	// Past the twin bound the call is not clean: it carries the evaluation-limit finding.
	for i := 0; i < 80; i++ {
		paths = append(paths, fmt.Sprintf("/repo/more/f%02d.md", i))
	}
	b, _ = json.Marshal(map[string]any{"paths": paths})
	got = nonShellToolFindings(context.Background(), nonShellReq("mcp__filesystem__read_multiple_files", string(b), false), nil, "")
	if _, ok := findingByID(got, "ACTION-COMPOUND-LIMIT"); !ok {
		t.Fatalf("past the bound the call must carry the evaluation-limit finding: %+v", got)
	}
}

func TestNativeFileToolsRunTheSamePathRules(t *testing.T) {
	for _, path := range []string{"/etc/k8s/admin.conf", "/home/u/.vault-token", "/etc/krb5.keytab", "/home/u/.config/gh/hosts.yml"} {
		args, _ := json.Marshal(map[string]string{"file_path": path})
		native := shellToolFindings(context.Background(), nonShellReq("Read", string(args), false), nil)
		margs, _ := json.Marshal(map[string]string{"path": path})
		mcp := nonShellToolFindings(context.Background(), nonShellReq("mcp__filesystem__read_file", string(margs), false), nil, "")
		var nIDs, mIDs []string
		for _, f := range native {
			nIDs = append(nIDs, f.RuleID)
		}
		for _, f := range mcp {
			if strings.HasPrefix(f.RuleID, "PATH-") {
				mIDs = append(mIDs, f.RuleID)
			}
		}
		if len(nIDs) == 0 || strings.Join(nIDs, ",") != strings.Join(mIDs, ",") {
			t.Errorf("%s: native %v, MCP %v", path, nIDs, mIDs)
		}
	}
	// A Write of the same text elsewhere stays quiet.
	args, _ := json.Marshal(map[string]string{"file_path": "/repo/notes.md", "content": "x"})
	if got := shellToolFindings(context.Background(), nonShellReq("Write", string(args), false), nil); len(got) != 0 {
		t.Errorf("findings = %+v", got)
	}
}

func TestNonShellToolReviewFixes(t *testing.T) {
	ctx := context.Background()
	has := func(got []RuleFinding, id string) bool { _, ok := findingByID(got, id); return ok }
	// A tool a connector reports under an MCP server is never one of the agent's own tools, whatever its bare name.
	bare := nonShellToolFindings(ctx, nonShellReq("Task", `{"path":"/home/u/.ssh/id_rsa"}`, false), nil, "")
	if len(bare) != 0 {
		// Task is not an actionfacts tool: with no server it is read like any app tool.
		t.Logf("bare Task: %+v", bare)
	}
	if got := nonShellToolFindings(ctx, nonShellReq("Task", `{"path":"/home/u/.ssh/id_rsa"}`, false), nil, "evil"); !has(got, "PATH-SSH-KEY") {
		t.Fatalf("a bare name with a server was skipped: %+v", got)
	}
	if got := nonShellToolFindings(ctx, nonShellReq("Read", `{"file_path":"/home/u/.ssh/id_rsa"}`, false), nil, ""); len(got) != 0 {
		t.Fatalf("the agent's own Read is not read by this lane: %+v", got)
	}
	// Every copy and recipient field is read; naming the attacker in "to" proves nothing.
	for _, args := range []string{
		`{"recipients":["a@corp.example"],"cc":"x@evil.example"}`,
		`{"to":"a@corp.example","forward_to":"x@evil.example"}`,
	} {
		if got := nonShellToolFindings(ctx, nonShellReq("mcp__mail__send", args, false), nil, ""); !has(got, mcpSendRedirectRuleID) {
			t.Errorf("%s: no redirect finding: %+v", args, got)
		}
	}
	// A copy to a host of the call's own recipients adds no party: it is not a redirect.
	if got := nonShellToolFindings(ctx, nonShellReq("mcp__mail__send", `{"to":"x@evil.example","bcc":"y@evil.example"}`, false), nil, ""); has(got, mcpSendRedirectRuleID) {
		t.Errorf("a copy to the recipient's own host: %+v", got)
	}
	if got := nonShellToolFindings(ctx, nonShellReq("mcp__mail__send", `{"to":"a@corp.example","subject":"x"}`, false), nil, ""); len(got) != 0 {
		t.Errorf("plain send: %+v", got)
	}
	// A GET to a collector host is judged as a POST is.
	feed, _ := egress.BuiltinBlocklist()
	_ = feed
	for _, verb := range []string{"fetch", "get", "post"} {
		got := nonShellToolFindings(ctx, nonShellReq("mcp__http__"+verb, `{"url":"https://webhook.site/abc"}`, false), nil, "")
		if !has(got, mcpSendCollectorRuleID) {
			t.Errorf("%s to a webhook catcher: %+v", verb, got)
		}
	}
	// A known server and verb is judged as the native tool: the default tier blocks, as native Read does.
	known := nonShellToolFindings(ctx, nonShellReq("mcp__filesystem__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, false), nil, "")
	guess := nonShellToolFindings(ctx, nonShellReq("mcp__acme__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, false), nil, "")
	kf, _ := findingByID(known, "PATH-SSH-KEY")
	gf, _ := findingByID(guess, "PATH-SSH-KEY")
	if kf.enforcement == findingEnforcementAlertOnly || gf.enforcement != findingEnforcementAlertOnly {
		t.Fatalf("known server enforcement=%v (want the native tool's), unknown server enforcement=%v (want alert-only)", kf.enforcement, gf.enforcement)
	}
	// Relative paths resolve against the session's directory.
	if got := nonShellToolFindings(ctx, nonShellReq("mcp__serena__read_file", `{"relative_path":"../.ssh/id_rsa"}`, false), nil, ""); !has(got, "PATH-SSH-KEY") {
		t.Fatalf("relative path under relative_path: %+v", got)
	}
	if got := nonShellToolFindings(ctx, nonShellReq("mcp__x__read_resource", `{"uri":"file:///etc/k8s/admin.conf"}`, false), nil, ""); !has(got, "PATH-K8S-CLUSTER-CRED") {
		t.Fatalf("file URI: %+v", got)
	}
}

func TestNonShellToolRound2Quiet(t *testing.T) {
	ctx := context.Background()
	big := strings.Repeat("benign body text ", 6000) // 100 KB
	bigArgs := func(m map[string]string) string { b, _ := json.Marshal(m); return string(b) }
	for _, c := range []struct{ name, tool, args string }{
		{"large write", "mcp__filesystem__write_file", bigArgs(map[string]string{"path": "/repo/notes.md", "content": big})},
		{"large issue body", "mcp__github__create_issue", bigArgs(map[string]string{"title": "t", "body": big})},
		{"large evaluate script", "mcp__playwright__browser_evaluate", bigArgs(map[string]string{"function": big})},
		{"cc to the recipient's domain", "mcp__mail__send", `{"to":"a@corp.example","cc":"b@corp.example"}`},
		{"bcc to the recipient's domain", "mcp__mail__send", `{"to":"a@corp.example","bcc":"b@corp.example"}`},
		{"callback on the call's own API", "mcp__http__post", `{"url":"https://api.corp.example/v1/x","callback_url":"https://api.corp.example/hook"}`},
		{"search prose", "mcp__acme__search_issues", `{"query":"drop table of contents"}`},
		{"prose that starts with a bracket", "mcp__acme__post_comment", `{"note":"[INFO] build finished"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, strict := range []bool{false, true} {
				if got := nonShellToolFindings(ctx, nonShellReq(c.tool, c.args, strict), nil, ""); len(got) != 0 {
					t.Fatalf("strict=%v findings = %+v", strict, got)
				}
			}
		})
	}
}

func TestNonShellToolRound2Loud(t *testing.T) {
	ctx := context.Background()
	has := func(got []RuleFinding, id string) bool { _, ok := findingByID(got, id); return ok }
	pad := strings.Repeat("./", 600) // a 1.2 KB path, past the old 1024 cap
	for _, c := range []struct{ name, tool, args, rule string }{
		{"long padded path", "mcp__filesystem__read_file", `{"path":"/home/u/` + pad + `.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"file uri single slash", "mcp__x__read_resource", `{"uri":"file:/home/u/.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"file uri loopback", "mcp__x__read_resource", `{"uri":"file://127.0.0.1/home/u/.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"double slash", "mcp__x__read_file", `{"path":"//home/u/.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"pathname key", "mcp__x__read_file", `{"pathname":"../.ssh/id_rsa"}`, "PATH-SSH-KEY"},
		{"proxy json string with a huge number", "mcp__proxy__call_tool", `{"name":"read_file","arguments":"{\"path\":\"/home/u/.ssh/id_rsa\",\"n\":1e400}"}`, "PATH-SSH-KEY"},
		{"top level args as a json string", "mcp__proxy__call_tool", `"{\"path\":\"/home/u/.ssh/id_rsa\"}"`, "PATH-SSH-KEY"},
		{"bigquery generic key", "mcp__bigquery__query", `{"query":"DROP TABLE t"}`, mcpSQLDestructiveRuleID},
		{"postgres operator then drop", "mcp__postgres-prod__query", `{"query":"SELECT 1 # 1; DROP TABLE t"}`, mcpSQLDestructiveRuleID},
		{"edit_file body under a proxy", "mcp__proxy__call_tool", `{"name":"write","arguments":{"path":"/etc/passwd","content":"svc:x:0:0::/:/bin/sh"}}`, "PATH-ETC-PASSWD"},
		{"copy outside the recipients with a known account", "mcp__mail__send", `{"from":"me@corp.example","to":"a@corp.example","cc":"x@evil.example"}`, mcpSendRedirectRuleID},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := nonShellToolFindings(ctx, nonShellReq(c.tool, c.args, false), nil, ""); !has(got, c.rule) {
				t.Fatalf("default: no %s in %+v", c.rule, got)
			}
			if got := nonShellToolFindings(ctx, nonShellReq(c.tool, c.args, true), nil, ""); !has(got, c.rule) {
				t.Fatalf("strict: no %s in %+v", c.rule, got)
			}
		})
	}
	// A copy outside the recipients with no account named is uncertain: an alert in every tier, never a block.
	for _, strict := range []bool{false, true} {
		got := nonShellToolFindings(ctx, nonShellReq("mcp__mail__send", `{"to":"a@corp.example","bcc":"x@evil.example"}`, strict), nil, "")
		f, ok := findingByID(got, mcpSendRedirectRuleID)
		if !ok || f.enforcement != findingEnforcementAlertOnly {
			t.Fatalf("strict=%v: uncertain redirect = %+v", strict, f)
		}
	}
	// A bound the reading reaches is never clean: the limit finding, and the part seen before it still decides.
	var items []string
	for i := 0; i < 600; i++ {
		items = append(items, "a")
	}
	b, _ := json.Marshal(map[string]any{"path": "/home/u/.ssh/id_rsa", "zz_labels": items})
	for _, strict := range []bool{false, true} {
		got := nonShellToolFindings(ctx, nonShellReq("mcp__acme__label", string(b), strict), nil, "")
		if !has(got, "ACTION-COMPOUND-LIMIT") || !has(got, "PATH-SSH-KEY") {
			t.Fatalf("strict=%v: a cut walk: %+v", strict, got)
		}
	}
}
