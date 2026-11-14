// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"encoding/json"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func mapOf(t *testing.T, tool, args string) Mapping {
	t.Helper()
	m, err := Map(tool, json.RawMessage(args), "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func kinds(m Mapping) []Kind {
	var out []Kind
	for _, e := range m.Effects {
		out = append(out, e.Kind)
	}
	return out
}

func TestTableValidates(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitNameAndTokens(t *testing.T) {
	cases := []struct{ tool, server, name string }{
		{"mcp__filesystem__read_file", "filesystem", "read_file"},
		{"mcp__bench__fs_read", "bench", "fs_read"},
		{"fs.read_batch", "fs", "read_batch"},
		{"send_email", "", "send_email"},
		{"mcp__only", "", "only"},
	}
	for _, c := range cases {
		if s, n := SplitName(c.tool); s != c.server || n != c.name {
			t.Errorf("SplitName(%q) = %q, %q; want %q, %q", c.tool, s, n, c.server, c.name)
		}
	}
	if got := Tokens("readFile_v2-batch"); !slices.Equal(got, []string{"read", "file", "v2", "batch"}) {
		t.Errorf("Tokens = %v", got)
	}
}

func TestFileToolsMapToPathEffects(t *testing.T) {
	m := mapOf(t, "mcp__filesystem__read_file", `{"path":"/etc/shadow"}`)
	if m.Family != FamilyFS || m.Verb != KindRead || len(m.Effects) != 1 ||
		m.Effects[0].Kind != KindRead || m.Effects[0].Path != "/etc/shadow" || m.Effects[0].Reason != "mcp_semantics" {
		t.Fatalf("mapping = %+v", m)
	}
	m = mapOf(t, "mcp__bench__fs_read_batch", `{"paths":["/a/b","/c/d"]}`)
	if len(m.Effects) != 2 {
		t.Fatalf("batch effects = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__filesystem__write_file", `{"path":"/tmp/x","content":"hi"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindWrite {
		t.Fatalf("write = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__filesystem__delete_file", `{"path":"/tmp/x"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindDelete {
		t.Fatalf("delete = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__x__copy", `{"src":"/a/in","dest":"/b/out"}`)
	// dest is written, src is read, whatever the verb of the tool name says.
	got := map[string]Kind{}
	for _, e := range m.Effects {
		got[e.Path] = e.Kind
	}
	if got["/a/in"] != KindRead || got["/b/out"] != KindWrite {
		t.Fatalf("copy effects = %+v", m.Effects)
	}
}

func TestUnknownStaysUnknown(t *testing.T) {
	m := mapOf(t, "mcp__crm__lookup", `{"customer_id":"c-1","fields":["name"]}`)
	if len(m.Effects) != 0 || m.RoleKnown {
		t.Fatalf("a tool with no recognised name, verb or effect must stay unknown: %+v", m)
	}
	// A shape the table cannot place is not clean: Known is false, the caller
	// decides. Non-JSON-object arguments yield no effects.
	for _, args := range []string{``, `null`, `[1,2]`, `"str"`, `{`} {
		if m := mapOf(t, "mcp__a__b", args); len(m.Effects) != 0 {
			t.Errorf("args %q gave effects %+v", args, m.Effects)
		}
	}
}

func TestPathLikeValuesUnderOtherKeys(t *testing.T) {
	m := mapOf(t, "mcp__a__do_thing", `{"thing":"/home/u/.aws/credentials"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindRead {
		t.Fatalf("an absolute path under an unknown key is a guessed read: %+v", m.Effects)
	}
	for _, v := range []string{"https://h/x", "a@b.example", "hello world", "/", "/a b", "*.go", "line1\nline2"} {
		b, _ := json.Marshal(map[string]string{"thing": v})
		if m := mapOf(t, "mcp__a__do_thing", string(b)); len(m.Effects) != 0 {
			t.Errorf("value %q must not be a path: %+v", v, m.Effects)
		}
	}
}

func TestExistenceChecksAreListingsNotReads(t *testing.T) {
	m := mapOf(t, "mcp__files__check_file_exists", `{"filepath":"/home/u/.ssh/id_rsa"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindList {
		t.Fatalf("effects = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__files__read_file", `{"filepath":"/home/u/.ssh/id_rsa"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindRead {
		t.Fatalf("effects = %+v", m.Effects)
	}
}

func TestSendDestinations(t *testing.T) {
	m := mapOf(t, "mcp__mail__send", `{"to":"a@corp.example","bcc":"b@other.example"}`)
	var primary, redirect int
	for _, e := range m.Effects {
		if e.Kind != KindNetSend {
			t.Fatalf("effect %+v", e)
		}
		switch e.Role {
		case RolePrimary:
			primary++
			if e.Host != "corp.example" {
				t.Errorf("host = %q", e.Host)
			}
		case RoleRedirect:
			redirect++
		}
	}
	if primary != 1 || redirect != 1 {
		t.Fatalf("effects = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__http__post", `{"url":"https://Paste.Example:8443/x"}`)
	if len(m.Effects) != 1 || m.Effects[0].Host != "paste.example" || m.Effects[0].Kind != KindNetSend {
		t.Fatalf("post = %+v", m.Effects)
	}
	m = mapOf(t, "mcp__http__get", `{"url":"https://h.example/x"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindNetFetch {
		t.Fatalf("get = %+v", m.Effects)
	}
}

func TestSQLClasses(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT * FROM users WHERE id = 1", nil},
		{"DELETE FROM sessions WHERE expires < now()", nil},
		{"INSERT INTO t VALUES (1)", nil},
		{"UPDATE t SET name = 'x' WHERE id = 1", nil},
		{"DROP TABLE IF EXISTS tmp_x", []string{SQLDrop}},
		{"drop database staging", []string{SQLDrop}},
		{"TRUNCATE TABLE warehouse.orders", []string{SQLTruncate}},
		{"DELETE FROM cache", []string{SQLDeleteAll}},
		{"/* x */ DELETE FROM cache -- all", []string{SQLDeleteAll}},
		{"GRANT ALL ON db.* TO 'u'", []string{SQLPrivilege}},
		{"UPDATE user_permissions SET role='admin' WHERE dept='a'", []string{SQLPrivilege}},
		{"UPDATE audit_config SET enabled=false WHERE scope='all'", []string{SQLAuditOff}},
		{"UPDATE log_config SET rotation_enabled=false WHERE id=1", []string{SQLAuditOff}},
		{"UPDATE users SET password=md5('x') WHERE role='admin'", []string{SQLCredential}},
		{"SELECT 1; DROP TABLE t", []string{SQLDrop}},
		{"SELECT 'a;b DROP TABLE x'", nil},
		{"UPDATE products SET enabled=false WHERE id=3", nil},
		{"UPDATE settings SET logging_level = 0 WHERE id = 1", nil},
		{"GRANT access to the new hire", nil},
		{"DELETE FROM cache WHERE expires < 5", nil},
		{"drop table of contents", nil},
		{"truncate table of contents please", nil},
		{"WITH old AS (SELECT id FROM t WHERE x) SELECT * FROM old", nil},
		{"WITH old AS (SELECT id FROM t) DELETE FROM t", []string{SQLDeleteAll}},
		{"WITH a AS (SELECT 1), b AS (SELECT 2) DELETE FROM t WHERE 1=1", []string{SQLDeleteAll}},
		{"DELETE FROM t WHERE 1=1", []string{SQLDeleteAll}},
		{"DELETE FROM t WHERE id = 1 OR 1=1", []string{SQLDeleteAll}},
		{"DELETE FROM t WHERE true;", []string{SQLDeleteAll}},
		{"SELECT 'it\\'s'; DROP TABLE users", []string{SQLDrop}},
		{"/*!50000 DROP TABLE users */", []string{SQLDrop}},
		{"/*! DELETE FROM users */", []string{SQLDeleteAll}},
		{"UPDATE feature SET mfa_enabled = false", []string{SQLAuditOff}},
	}
	for _, c := range cases {
		var got []string
		classes := ClassifySQL(c.sql)
		for _, k := range classes {
			got = append(got, k.Class)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("ClassifySQL(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
	m := mapOf(t, "mcp__db__execute", `{"database":"Prod_DB","sql":"TRUNCATE orders"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindSQL {
		t.Fatalf("sql effect = %+v", m.Effects)
	}
	// A generic "query" key is SQL only for a db tool or when it starts like SQL.
	if m := mapOf(t, "mcp__search__find", `{"query":"cats and dogs"}`); len(m.Effects) != 0 {
		t.Fatalf("a search query is not SQL: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__search__find", `{"query":"best drop shipping suppliers"}`); len(m.Effects) != 0 {
		t.Fatalf("prose that merely contains SQL words is not SQL: %+v", m.Effects)
	}
}

func TestSettings(t *testing.T) {
	for _, c := range []struct {
		args string
		want bool
	}{
		{`{"skip_2fa":true}`, true},
		{`{"skip_2fa":false}`, false},
		{`{"verifySsl":false}`, true},
		{`{"verify_ssl":true}`, false},
		{`{"include_sensitive_data":true,"log_destination":"x"}`, true},
		{`{"acl":"public-read"}`, true},
		{`{"acl":"private"}`, false},
		{`{"operations":[{"op":"disable_mfa"}]}`, true},
		{`{"operations":[{"op":"reset_password"}]}`, false},
	} {
		m := mapOf(t, "mcp__admin__configure", c.args)
		got := slices.Contains(kinds(m), KindSetting)
		if got != c.want {
			t.Errorf("%s: setting effect = %v, want %v (%+v)", c.args, got, c.want, m.Effects)
		}
	}
}

func TestCodeToolsAndDecodeExec(t *testing.T) {
	m := mapOf(t, "mcp__sandbox__execute_code", `{"code":"print(1)","language":"python"}`)
	if len(m.Effects) != 1 || m.Effects[0].Kind != KindExec {
		t.Fatalf("code effect = %+v", m.Effects)
	}
	// A "code" argument of a tool that is not a code tool is not code.
	if m := mapOf(t, "mcp__crm__get_contact", `{"code":"X-12"}`); len(m.Effects) != 0 {
		t.Fatalf("effects = %+v", m.Effects)
	}
	for code, want := range map[string]bool{
		"print('hello')": false,
		"import base64\nx = base64.b64decode(s)\nprint(x)": false,
		"exec(base64.b64decode(blob).decode())":            true,
		"eval(atob(s))":                                    true,
		"exec(open('f').read())":                           false,
	} {
		if got := DecodeExec(code); got != want {
			t.Errorf("DecodeExec(%q) = %v, want %v", code, got, want)
		}
	}
}

func TestBounds(t *testing.T) {
	var paths []string
	for i := 0; i < 600; i++ {
		paths = append(paths, "/a/b")
	}
	b, _ := json.Marshal(map[string]any{"paths": paths})
	m := mapOf(t, "mcp__fs__read_batch", string(b))
	if len(m.Effects) > maxEffects || !m.Truncated.Any() {
		t.Fatalf("effects = %d truncated = %v", len(m.Effects), m.Truncated)
	}
	deep := `{"a":` + string(make([]byte, 0))
	for i := 0; i < 50; i++ {
		deep += `{"a":`
	}
	deep += `"/x/y"` + string(append([]byte(nil), []byte("}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}")...))
	if _, err := Map("mcp__a__b", json.RawMessage(deep), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRules(t *testing.T) {
	if got := PathRules("read", "/etc/k8s/admin.conf", ""); !slices.Equal(got, []string{"PATH-K8S-CLUSTER-CRED"}) {
		t.Errorf("k8s = %v", got)
	}
	if got := PathRules("read", `/home/u/.config/gh/hosts.yml`, ""); !slices.Equal(got, []string{"PATH-CRED-STORE-USER"}) {
		t.Errorf("gh = %v", got)
	}
	if got := PathRules("write", "/etc/passwd", "echo svc:x:0:0::/:/bin/sh >> /etc/passwd"); !slices.Equal(got, []string{"PATH-ETC-PASSWD"}) {
		t.Errorf("passwd write = %v", got)
	}
	if got := PathRules("append", "/etc/passwd", "echo git:x:1000:1000::/home/git:/bin/bash >> /etc/passwd"); len(got) != 0 {
		t.Errorf("adding an ordinary account line is not a uid-0 line: %v", got)
	}
	if got := PathRules("read", "/etc/passwd", ""); len(got) != 0 {
		t.Errorf("a passwd read is not in this table: %v", got)
	}
	if got := PathRules("append", `/etc/cron.d/x`, "echo '0 3 * * * root /home/u/clean.sh' | tee -a /etc/cron.d/x"); !slices.Equal(got, []string{"CMD-PERSIST-SYSTEM-SCHEDULE"}) {
		t.Errorf("cron = %v", got)
	}
	if got := PathRules("write", "/etc/cron.d/x", "echo '@reboot root /opt/app/worker.py' > /etc/cron.d/x"); len(got) != 0 {
		t.Errorf("a root job from a system path is ordinary administration: %v", got)
	}
	if got := PathRules("read", "/run/secrets/db_password", ""); len(got) != 0 {
		t.Errorf("container secrets are the workload's own input: %v", got)
	}
	if got := PathRules("read", "/repo/docs/etc/k8s/admin.conf.md", ""); len(got) != 0 {
		t.Errorf("an unrooted look-alike matched: %v", got)
	}
	if got := CommandRules("chmod", []string{"chmod", "u+s", "/x"}); !slices.Equal(got, []string{"CMD-PRIV-SETUID"}) {
		t.Errorf("chmod = %v", got)
	}
	if got := CommandRules("chmod", []string{"chmod", "644", "/x"}); len(got) != 0 {
		t.Errorf("chmod 644 = %v", got)
	}
	if got := CommandRules("vault", []string{"vault", "token", "lookup"}); !slices.Equal(got, []string{"CMD-SECRET-LOOKUP"}) {
		t.Errorf("vault = %v", got)
	}
	if got := CommandRules("vault", []string{"vault", "status"}); len(got) != 0 {
		t.Errorf("vault status = %v", got)
	}
	if got := CommandRules("git", []string{"git", "show", "main:config/secrets.yaml"}); !slices.Equal(got, []string{"CMD-GIT-SHOW-SECRET"}) {
		t.Errorf("git show of a secret file = %v", got)
	}
	for _, a := range []string{"main:stack/scripts/tool_gating.env.sh", "HEAD:internal/gateway/user_scoped_credentials.go", "x:docs/stop-a-secret-upload.mdx", "v1:src/environment.go", "r:secret.txt"} {
		if got := CommandRules("git", []string{"git", "show", a}); len(got) != 0 {
			t.Errorf("git show %s = %v", a, got)
		}
	}
	if !ShellCandidate(`type C:\Users\u\.config\gh\hosts.yml`) {
		t.Error("a Windows spelling of a trigger word is a candidate")
	}
	if !ShellCandidate("tool --reveal x") || ShellCandidate("ls -la /tmp") {
		t.Error("ShellCandidate")
	}
}

func FuzzMap(f *testing.F) {
	f.Add("mcp__a__b", `{"path":"/x"}`)
	f.Add("fs.read", `{"paths":["/a"]}`)
	f.Add("", `{"sql":"drop table x"}`)
	f.Fuzz(func(t *testing.T, tool, args string) {
		m, err := Map(tool, json.RawMessage(args), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Effects) > maxEffects {
			t.Fatalf("effects over the bound: %d", len(m.Effects))
		}
		for _, e := range m.Effects {
			if e.Reason != "mcp_semantics" {
				t.Fatalf("effect without the mcp_semantics reason: %+v", e)
			}
		}
	})
}

func BenchmarkMapTypicalCall(b *testing.B) {
	args := json.RawMessage(`{"database":"ops","sql":"SELECT id, name FROM users WHERE id = 42 ORDER BY name LIMIT 10","limit":10}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Map("mcp__postgres__query", args, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMapFileBatch(b *testing.B) {
	args := json.RawMessage(`{"paths":["/repo/a.md","/repo/b.md","/repo/c.md","/repo/docs/setup.md","/repo/docs/auth.md"]}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Map("mcp__filesystem__read_multiple_files", args, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFileURIsAndRelativeKeys(t *testing.T) {
	for _, c := range []struct{ tool, args, want string }{
		{"mcp__filesystem__read_file", `{"path":"file:///etc/shadow"}`, "/etc/shadow"},
		{"mcp__x__read_resource", `{"uri":"file://localhost/etc/shadow"}`, "/etc/shadow"},
		{"mcp__serena__read_file", `{"relative_path":"../.ssh/id_rsa"}`, "../.ssh/id_rsa"},
		{"mcp__x__read_file", `{"fileName":"../.ssh/id_rsa"}`, "../.ssh/id_rsa"},
		{"mcp__jetbrains__get_file_text_by_path", `{"pathInProject":"../.ssh/id_rsa"}`, "../.ssh/id_rsa"},
		{"mcp__x__read_file", `{"FILE_PATH":"/etc/shadow"}`, "/etc/shadow"},
		{"mcp__proxy__call_tool", `{"name":"read_file","arguments":"{\"path\":\"/etc/shadow\"}"}`, "/etc/shadow"},
		{"mcp__proxy__call_tool", `{"name":"read_file","arguments":{"path":"/etc/shadow"}}`, "/etc/shadow"},
	} {
		m := mapOf(t, c.tool, c.args)
		found := false
		for _, e := range m.Effects {
			if e.Path == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %s: no path effect %q in %+v", c.tool, c.args, c.want, m.Effects)
		}
	}
	// A file URI of another host is not a local path.
	if m := mapOf(t, "mcp__x__read_resource", `{"uri":"file://server/share/x"}`); len(m.Effects) != 0 {
		t.Errorf("remote file URI: %+v", m.Effects)
	}
}

func TestBoundsAreGenerousAndReported(t *testing.T) {
	// A path after 64 filler items, 17 filler paths, 48 filler keys and 6 levels is still read.
	var items []string
	for i := 0; i < 100; i++ {
		items = append(items, "/repo/docs/f.md")
	}
	items = append(items, "/home/u/.ssh/id_rsa")
	b, _ := json.Marshal(map[string]any{"paths": items})
	m := mapOf(t, "mcp__filesystem__read_multiple_files", string(b))
	last := m.Effects[len(m.Effects)-1]
	if last.Path != "/home/u/.ssh/id_rsa" || m.Truncated.Any() {
		t.Fatalf("last effect %+v truncated=%v", last, m.Truncated)
	}
	deep := `{"path":"/home/u/.ssh/id_rsa"}`
	for i := 0; i < 8; i++ {
		deep = `{"l":` + deep + `}`
	}
	if m := mapOf(t, "mcp__x__read_file", deep); len(m.Effects) != 1 || m.Truncated.Any() {
		t.Fatalf("depth 8: %+v truncated=%v", m.Effects, m.Truncated)
	}
	// Past the bounds the mapping says so.
	deep = `{"path":"/home/u/.ssh/id_rsa"}`
	for i := 0; i < 40; i++ {
		deep = `{"l":` + deep + `}`
	}
	if m := mapOf(t, "mcp__x__read_file", deep); !m.Truncated.Any() {
		t.Fatal("a call past the depth bound must report Truncated")
	}
}

func TestGenericQueryKeyIsSQLOnlyForDatabaseTools(t *testing.T) {
	for _, c := range []struct {
		tool, args string
		sql        bool
	}{
		{"mcp__search__search_issues", `{"query":"grant access to the new hire"}`, false},
		{"mcp__github__search_code", `{"q":"delete from cache where"}`, false},
		{"mcp__web__web_search", `{"query":"drop table cats"}`, false},
		{"mcp__web__find", `{"query":"truncate table of contents"}`, false},
		{"mcp__postgres__query", `{"query":"DROP TABLE users"}`, true},
		{"mcp__db__execute", `{"query":"TRUNCATE orders"}`, true},
		{"mcp__x__run_query", `{"query":"DELETE FROM cache"}`, true},
		{"mcp__x__execute_statement", `{"query":"GRANT ALL ON db.* TO u"}`, true},
		{"mcp__x__lookup", `{"sql":"DROP TABLE users"}`, true},
	} {
		got := slices.Contains(kinds(mapOf(t, c.tool, c.args)), KindSQL)
		if got != c.sql {
			t.Errorf("%s %s: sql effect = %v, want %v", c.tool, c.args, got, c.sql)
		}
	}
}

func TestReviewRound2Mapping(t *testing.T) {
	has := func(m Mapping, path string) bool {
		for _, e := range m.Effects {
			if e.Path == path {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ tool, args, want string }{
		{"mcp__x__read_resource", `{"uri":"file:/home/u/.ssh/id_rsa"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__x__read_resource", `{"uri":"file://127.0.0.1/home/u/.ssh/id_rsa"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__x__read_resource", `{"uri":"file://[::1]/home/u/.ssh/id_rsa"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__x__read_resource", `{"uri":"file:///home/u/My%20Docs/.ssh/id_rsa"}`, "/home/u/My Docs/.ssh/id_rsa"},
		{"mcp__x__read_file", `{"path":"//home/u/.ssh/id_rsa"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__x__do", `{"thing":"/home/u/My Documents/../.ssh/id_rsa"}`, "/home/u/My Documents/../.ssh/id_rsa"},
		{"mcp__x__read_file", `{"pathname":"../.ssh/id_rsa"}`, "../.ssh/id_rsa"},
		{"mcp__x__read_file", `{"path_name":"../.ssh/id_rsa"}`, "../.ssh/id_rsa"},
		{"mcp__proxy__call_tool", `{"name":"read_file","arguments":"{\"path\":\"/home/u/.ssh/id_rsa\",\"n\":1e400}"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__proxy__call_tool", `{"name":"read_file","arguments":"{\"path\":\"/home/u/.ssh/id_rsa\",\"n\":NaN}"}`, "/home/u/.ssh/id_rsa"},
		{"mcp__proxy__call_tool", `"{\"path\":\"/home/u/.ssh/id_rsa\"}"`, "/home/u/.ssh/id_rsa"},
	} {
		if m := mapOf(t, c.tool, c.args); !has(m, c.want) {
			t.Errorf("%s %s: no path effect %q in %+v", c.tool, c.args, c.want, m.Effects)
		}
	}
	// A path past the path bound is judged and the bound is recorded.
	long := "/repo/" + strings.Repeat("./", maxPath/2) + "f.md"
	if m := mapOf(t, "mcp__filesystem__read_file", `{"path":"`+long+`"}`); !has(m, long) || !m.Truncated.Has(bounded.Bytes) {
		t.Errorf("long path: truncated=%v effects=%d", m.Truncated, len(m.Effects))
	}
	// A file URI of another host is unplaced: unread, never clean.
	if m := mapOf(t, "mcp__x__read_resource", `{"uri":"file://server/share/x"}`); !m.Truncated.Any() {
		t.Errorf("remote file URI: %+v", m)
	}
	// Nesting past the bound, and a document the reader cannot parse, are recorded.
	deep := `{"path":"/home/u/.ssh/id_rsa"}`
	for i := 0; i < maxNested+1; i++ {
		b, _ := json.Marshal(deep)
		deep = `{"arguments":` + string(b) + `}`
	}
	if m := mapOf(t, "mcp__x__read_file", deep); !m.Truncated.Has(bounded.Depth) {
		t.Errorf("nested JSON strings past the bound: %v", m.Truncated)
	}
	// A Python-literal document is read; one no parser reads is text.
	if m := mapOf(t, "mcp__x__do", `{"arguments":"{'path': '/home/u/.ssh/id_rsa', 'ok': True}"}`); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("python literal: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__x__do", `{"arguments":"{\"path\": /home/u/.ssh/id_rsa oops}"}`); m.Truncated.Any() || !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("unparseable document read as text: %v %+v", m.Truncated, m.Effects)
	}
	// Prose that starts with a bracket is text.
	for _, v := range []string{"[INFO] done", "{{name}} said hi", "[1] see below", "[formatted HTML content]", "[{'entityName': 'AI', 'text': 'x'}]"} {
		b, _ := json.Marshal(map[string]string{"note": v})
		if m := mapOf(t, "mcp__x__post_comment", string(b)); m.Truncated.Any() {
			t.Errorf("%q marked truncated", v)
		}
	}
}

func TestLargeBodiesAreNotTruncated(t *testing.T) {
	body := strings.Repeat("benign text ", 8000) // 96 KB
	b, _ := json.Marshal(map[string]string{"path": "/repo/notes.md", "content": body})
	m := mapOf(t, "mcp__filesystem__write_file", string(b))
	if m.Truncated.Any() || m.Content == "" {
		t.Fatalf("a 96 KB write body: truncated=%v content=%d", m.Truncated, len(m.Content))
	}
	b, _ = json.Marshal(map[string]string{"body": body})
	if m := mapOf(t, "mcp__github__create_issue", string(b)); m.Truncated.Any() {
		t.Fatalf("a large issue body: %v", m.Truncated)
	}
	huge := strings.Repeat("a", maxString+1)
	b, _ = json.Marshal(map[string]string{"body": huge})
	if m := mapOf(t, "mcp__github__create_issue", string(b)); !m.Truncated.Has(bounded.Bytes) {
		t.Fatalf("a string past the byte bound is recorded: %v", m.Truncated)
	}
}

func TestContentIsCollectedFromNestedKeys(t *testing.T) {
	m := mapOf(t, "mcp__proxy__call_tool", `{"name":"write","arguments":{"path":"/etc/passwd","content":"svc:x:0:0::/:/bin/sh"}}`)
	if !strings.Contains(m.Content, "svc:x:0:0") {
		t.Errorf("nested content: %q", m.Content)
	}
	m = mapOf(t, "mcp__filesystem__edit_file", `{"path":"/etc/passwd","edits":[{"oldText":"a","newText":"svc:x:0:0::/:/bin/sh"}]}`)
	if !strings.Contains(m.Content, "svc:x:0:0") {
		t.Errorf("edit content: %q", m.Content)
	}
	// A plain prose write is data; a JSON body is read as arguments (the lead's decision).
	m = mapOf(t, "mcp__filesystem__write_file", `{"path":"/repo/c.md","content":"see /etc/shadow"}`)
	for _, e := range m.Effects {
		if e.Path == "/etc/shadow" {
			t.Errorf("prose body read as arguments: %+v", m.Effects)
		}
	}
}

func TestDatabaseServersByShape(t *testing.T) {
	for _, c := range []struct {
		tool, args string
		sql        bool
	}{
		{"mcp__bigquery__query", `{"query":"DROP TABLE t"}`, true},
		{"mcp__postgres-prod__query", `{"query":"DROP TABLE t"}`, true},
		{"mcp__my-sqlite__run", `{"query":"DROP TABLE t"}`, true},
		{"mcp__snowflake__execute", `{"query":"TRUNCATE orders"}`, true},
		{"mcp__acme__run_report", `{"query":"DROP TABLE t"}`, true},
		{"mcp__acme__search_docs", `{"query":"DROP TABLE t"}`, false},
		{"mcp__acme__lookup", `{"q":"GRANT ALL ON db.* TO u"}`, false},
	} {
		if got := slices.Contains(kinds(mapOf(t, c.tool, c.args)), KindSQL); got != c.sql {
			t.Errorf("%s %s: sql = %v, want %v", c.tool, c.args, got, c.sql)
		}
	}
}

func TestSQLDialectReadings(t *testing.T) {
	for _, c := range []struct {
		sql  string
		want bool
	}{
		{"SELECT 1 # 1; DROP TABLE t", true},      // PostgreSQL: # is an operator, the DROP runs
		{"SELECT $$'$$; DROP TABLE t; --'", true}, // PostgreSQL dollar quotes
		{"SELECT $q$ DROP TABLE t $q$", false},    // a string, read as one
		{"SELECT '$$'; SELECT '$$'", false},
		{"SELECT price FROM t WHERE cost = $1 AND id = $2", false},
	} {
		classes := ClassifySQL(c.sql)
		if got := len(classes) > 0; got != c.want {
			t.Errorf("ClassifySQL(%q) = %v, want drop=%v", c.sql, classes, c.want)
		}
	}
}

func TestAddressListsAndVisibleCopies(t *testing.T) {
	m := mapOf(t, "mcp__mail__send", `{"to":"A <a@x.com>, b@y.com; c@z.com","cc":"d@x.com","bcc":"e@w.com, f@v.com"}`)
	var prim, red []string
	for _, e := range m.Effects {
		if e.Role == RolePrimary {
			prim = append(prim, e.Host)
		}
		if e.Role == RoleRedirect {
			red = append(red, e.Host)
		}
	}
	slices.Sort(prim)
	slices.Sort(red)
	if !slices.Equal(prim, []string{"x.com", "y.com", "z.com"}) || !slices.Equal(red, []string{"v.com", "w.com"}) {
		t.Errorf("primary %v redirect %v", prim, red)
	}
}

func TestRound3Mapping(t *testing.T) {
	has := func(m Mapping, path string) bool {
		for _, e := range m.Effects {
			if e.Path == path {
				return true
			}
		}
		return false
	}
	// A value that starts with "file:" and is not a file URI is text.
	for _, v := range []string{"file: report.txt", "file:name", "FILE:notes", "file:"} {
		b, _ := json.Marshal(map[string]string{"pattern": v})
		if m := mapOf(t, "mcp__acme__grep", string(b)); m.Truncated.Any() || len(m.Effects) != 0 {
			t.Errorf("%q: %+v truncated=%v", v, m.Effects, m.Truncated)
		}
	}
	for _, v := range []string{"file:/etc/shadow", "file:///etc/shadow", "file://localhost/etc/shadow", "FILE:/etc/shadow"} {
		b, _ := json.Marshal(map[string]string{"uri": v})
		if m := mapOf(t, "mcp__x__read_resource", string(b)); !has(m, "/etc/shadow") {
			t.Errorf("%q not read: %+v", v, m.Effects)
		}
	}
	// A path a read tool receives under a content-style key is read; a write's body is data.
	if m := mapOf(t, "mcp__x__read_file", `{"text":"/home/u/.ssh/id_rsa"}`); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("path under text for a read tool: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__x__read_file", `{"data":"{\"path\":\"/home/u/.ssh/id_rsa\"}"}`); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("JSON under data for a read tool: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__filesystem__write_file", `{"path":"/repo/a.json","content":"{\"path\":\"/etc/shadow\"}"}`); has(m, "/etc/shadow") {
		t.Errorf("a JSON body is data for a write: %+v", m.Effects)
	}
	// A recipient field of more than 64 addresses is recorded.
	var list []string
	for i := 0; i < 600; i++ {
		list = append(list, "u"+strconv.Itoa(i)+"@x.com")
	}
	b, _ := json.Marshal(map[string]string{"bcc": strings.Join(list, ", ")})
	if m := mapOf(t, "mcp__mail__send", string(b)); !m.Truncated.Has(bounded.Items) {
		t.Errorf("a 600-address field: %v", m.Truncated)
	}
}

func TestRound4(t *testing.T) {
	has := func(m Mapping, path string) bool {
		for _, e := range m.Effects {
			if e.Path == path {
				return true
			}
		}
		return false
	}
	// SQL is read whole up to the string bound: a 900 KB benign seed is clean, an attack at its end is found.
	var seed strings.Builder
	for seed.Len() < 900_000 {
		seed.WriteString("INSERT INTO items (id, name) VALUES (1, 'alpha');\n")
	}
	b, _ := json.Marshal(map[string]string{"database": "d", "sql": seed.String()})
	if m := mapOf(t, "mcp__postgres__execute", string(b)); m.Truncated.Any() || len(m.Effects) != 0 {
		t.Fatalf("900 KB benign seed: truncated=%v effects=%+v", m.Truncated, m.Effects)
	}
	b, _ = json.Marshal(map[string]string{"database": "d", "sql": seed.String() + "DROP TABLE users;"})
	m := mapOf(t, "mcp__postgres__execute", string(b))
	if m.Truncated.Any() || !slices.Contains(kinds(m), KindSQL) {
		t.Fatalf("attack at the end of 900 KB: truncated=%v kinds=%v", m.Truncated, kinds(m))
	}
	// file: is a file URI only as one; only under a key that can hold a location.
	for _, v := range []string{"file:../lib", "File: report", "file:./x", "file:name"} {
		b, _ := json.Marshal(map[string]string{"path": v})
		if m := mapOf(t, "mcp__x__read_file", string(b)); m.Truncated.Any() {
			t.Errorf("%q truncated", v)
		}
	}
	// A real file URI is read from any argument value, decoded; a write's body stays data.
	for _, key := range []string{"pattern", "label", "ref", "anything"} {
		b, _ = json.Marshal(map[string]string{key: "file:///home/u/.ssh/id_rsa"})
		if m := mapOf(t, "mcp__x__do", string(b)); !has(m, "/home/u/.ssh/id_rsa") {
			t.Errorf("file URI under %s: %+v", key, m.Effects)
		}
	}
	b, _ = json.Marshal(map[string]string{"data": "file:///home/u%2F.ssh%2Fid_rsa"})
	if m := mapOf(t, "mcp__x__read_file", string(b)); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("encoded slashes: %+v", m.Effects)
	}
	b, _ = json.Marshal(map[string]string{"path": "/repo/a.md", "content": "file:///home/u/.ssh/id_rsa"})
	if m := mapOf(t, "mcp__filesystem__write_file", string(b)); has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("a write body is data: %+v", m.Effects)
	}
	// Content keys: read for a send, a proxy, a JSON value; data for a prose write.
	if m := mapOf(t, "mcp__mail__send", `{"to":"a@x.com","body":"/home/u/.ssh/id_rsa"}`); has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("a send body is data: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__proxy__call_tool", `{"name":"x","arguments":{"text":"/home/u/.ssh/id_rsa"}}`); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("a proxy text: %+v", m.Effects)
	}
	if m := mapOf(t, "mcp__filesystem__write_file", `{"path":"/repo/n.md","content":"/home/u/.ssh/id_rsa is the key"}`); has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("prose body read: %+v", m.Effects)
	}
	// Address lists: one string and an array share the items bound.
	var addrs []string
	for i := 0; i < 600; i++ {
		addrs = append(addrs, "u"+strconv.Itoa(i)+"@x.com")
	}
	b, _ = json.Marshal(map[string]string{"bcc": strings.Join(addrs, ", ")})
	one := mapOf(t, "mcp__mail__send", string(b))
	b, _ = json.Marshal(map[string][]string{"bcc": addrs})
	many := mapOf(t, "mcp__mail__send", string(b))
	if !one.Truncated.Has(bounded.Items) || !many.Truncated.Has(bounded.Items) {
		t.Errorf("string %v array %v", one.Truncated, many.Truncated)
	}
	// Lenient JSON: trailing commas, comments, Python repr; a JSON-shaped document no reading parses is unread.
	for _, doc := range []string{
		`{"path": "/home/u/.ssh/id_rsa",}`,
		"{\"path\": \"/home/u/.ssh/id_rsa\" /* c */}",
		"{\"path\": \"/home/u/.ssh/id_rsa\" // c\n}",
		`{'path': '/home/u/.ssh/id_rsa', 'ok': True,}`,
	} {
		b, _ := json.Marshal(map[string]string{"arguments": doc})
		if m := mapOf(t, "mcp__proxy__call_tool", string(b)); !has(m, "/home/u/.ssh/id_rsa") {
			t.Errorf("%q: %+v", doc, m.Effects)
		}
	}
	if m := mapOf(t, "mcp__proxy__call_tool", `{"arguments":"{\"path\": /home/u/.ssh/id_rsa oops}"}`); m.Truncated.Any() || !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("unparseable document read as text: %v %+v", m.Truncated, m.Effects)
	}
	// The verb of a proxy's tool name applies to proxy-shaped calls only.
	if m := mapOf(t, "mcp__x__do", `{"name":"write_file","path":"/etc/passwd"}`); m.Verb != "" {
		t.Errorf("a name beside a path is not a proxy: verb %q", m.Verb)
	}
	if m := mapOf(t, "mcp__proxy__call_tool", `{"name":"write_file","arguments":{"path":"/etc/passwd"}}`); m.Verb != KindWrite {
		t.Errorf("a proxy: verb %q", m.Verb)
	}
	// A callback is a callback, not a copy.
	m = mapOf(t, "mcp__http__post", `{"url":"https://api.x.com/v1","callback_url":"https://hooks.y.com/x"}`)
	var cb int
	for _, e := range m.Effects {
		if e.Role == RoleCallback {
			cb++
		}
	}
	if cb != 1 {
		t.Errorf("callback effects: %+v", m.Effects)
	}
}

func TestRound5(t *testing.T) {
	has := func(m Mapping, path string) bool {
		for _, e := range m.Effects {
			if e.Path == path {
				return true
			}
		}
		return false
	}
	// What a call writes or sends is data, whatever its spelling.
	for _, c := range []struct{ tool, args string }{
		{"mcp__filesystem__write_file", `{"path":"/repo/c.json","content":"{\"path\":\"/home/u/.ssh/id_rsa\"}"}`},
		{"mcp__filesystem__edit_file", `{"path":"/repo/c.json","edits":[{"oldText":"a","newText":"{\"path\":\"/home/u/.ssh/id_rsa\"}"}]}`},
		{"mcp__github__create_issue", `{"title":"t","body":"{\"path\":\"/home/u/.ssh/id_rsa\"}"}`},
		{"mcp__mail__send", `{"to":"a@x.com","body":"{\"path\":\"/home/u/.ssh/id_rsa\"}"}`},
		{"mcp__slack__post_message", `{"channel":"c","text":"/home/u/.ssh/id_rsa"}`},
	} {
		if m := mapOf(t, c.tool, c.args); has(m, "/home/u/.ssh/id_rsa") {
			t.Errorf("%s: a body read as arguments: %+v", c.tool, m.Effects)
		}
	}
	// A tool that neither writes nor sends reads the value; a file URI under a content key too.
	if m := mapOf(t, "mcp__x__read_file", `{"data":"file:///home/u/.ssh/id_rsa"}`); !has(m, "/home/u/.ssh/id_rsa") {
		t.Errorf("file URI under data for a read tool: %+v", m.Effects)
	}
	for _, key := range []string{"resource", "ref", "uris", "link", "document", "whatever"} {
		b, _ := json.Marshal(map[string]string{key: "file:///home/u/.ssh/id_rsa"})
		if m := mapOf(t, "mcp__x__open", string(b)); !has(m, "/home/u/.ssh/id_rsa") {
			t.Errorf("file URI under %s: %+v", key, m.Effects)
		}
	}
	// A native tool's arguments open the MCP walk only for a real file URI under a location key.
	if HasFileURIArg(json.RawMessage(`{"file_path":"/repo/package.json","content":"{\"dependencies\":{\"a\":\"file:../a\"}}"}`)) {
		t.Error("a file: dependency in a package.json body is text")
	}
	if HasFileURIArg(json.RawMessage(`{"pattern":"file: notes","ref":"file:../lib"}`)) {
		t.Error("text that starts with file: is not a file URI")
	}
	if !HasFileURIArg(json.RawMessage(`{"uri":"file:///etc/passwd"}`)) || !HasFileURIArg(json.RawMessage(`{"path":"file:/etc/passwd"}`)) {
		t.Error("a file URI under a location key")
	}
}
