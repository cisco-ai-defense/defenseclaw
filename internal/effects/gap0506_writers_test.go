// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP0506Writers: sqlite3 writes its database when the SQL changes it
// and reads it when every statement only reads; git config --file FILE
// writes or reads FILE. A form the closed reading does not accept (SQL from
// stdin, a dot-command, a scope option beside --file) is not fully known.
// At a2d6245be7 every sqlite3 call was an unknown program and every
// git config --file call unaccounted.
func TestGAP0506Writers(t *testing.T) {
	const state = "/home/u/.defenseclaw/audit.db"
	runR2(t, []r2case{
		{"sqlite delete", raLin, `sqlite3 ` + state + ` 'delete from audit_events'`, r2Verdict("K|write:" + state), false},
		{"sqlite insert batch", raLin, `sqlite3 -batch ` + state + ` "insert into t values('a;b')"`, r2Verdict("K|write:" + state), false},
		{"sqlite cte delete", raLin, `sqlite3 ` + state + ` 'with x as (select 1) delete from t'`, r2Verdict("K|write:" + state), false},
		{"sqlite two args", raLin, `sqlite3 ` + state + ` 'select 1' 'drop table t'`, r2Verdict("K|write:" + state), false},
		{"sqlite select", raLin, `sqlite3 ` + state + ` 'select count(*) from audit_events -- delete'`, r2Verdict("K|"), false},
		{"sqlite readonly", raLin, `sqlite3 -readonly ` + state + ` 'delete from t'`, r2Verdict("K|"), false},
		{"sqlite memory", raLin, `sqlite3 :memory: 'create table t(a)'`, r2Verdict("K|"), false},
		{"sqlite stdin", raLin, `sqlite3 ` + state, r2Verdict("U|write:" + state), false},
		{"sqlite dot shell", raLin, `sqlite3 ` + state + ` '.shell rm x'`, r2Verdict("U|write:" + state), false},
		{"sqlite attach", raLin, `sqlite3 ` + state + ` "attach '/tmp/x' as y"`, r2Verdict("U|write:" + state), false},
		{"sqlite cmd option", raLin, `sqlite3 -cmd '.shell x' ` + state + ` 'select 1'`, gap0506Unknown(), false},
		{"git config file set", raLin, `git config --file ` + r2Hook + ` a.b c`, r2Verdict("K|write:" + r2Hook), false},
		{"git config f add", raLin, `git config -f ` + r2Hook + ` --add a.b c`, r2Verdict("K|write:" + r2Hook), false},
		{"git config file= unset", raLin, `git config --file=` + r2Hook + ` --unset a.b`, r2Verdict("K|write:" + r2Hook), false},
		{"git config set file", raLin, `git config set --file ` + r2Hook + ` a.b c`, r2Verdict("K|write:" + r2Hook), false},
		{"git config file get", raLin, `git config --file ` + r2Hook + ` --get a.b`, r2Verdict("K|"), false},
		{"git config file one word", raLin, `git config --file ` + r2Hook + ` a.b`, r2Verdict("K|"), false},
		{"git config file global", raLin, `git config --global --file ` + r2Hook + ` a.b c`, gap0506Unknown(), false},
		{"git config file edit", raLin, `git config --file ` + r2Hook + ` --edit`, gap0506Unknown(), false},
		{"git config global", raLin, `git config --global a.b c`, gap0506Unknown(), false},
		{"ed delete write", raLin, `ed -s ` + r2Hook + ` <<< $'1d\nw\nq'`, r2Verdict("K|write:" + r2Hook), false},
		{"ed printf pipe", raLin, `printf '1d\nw\nq\n' | ed -s ` + r2Hook, r2Verdict("U|write:" + r2Hook), false},
		{"ed heredoc wq", raLin, "ed -s " + r2Hook + " <<'EOF'\n$a\nx\n.\nwq\nEOF", r2Verdict("K|write:" + r2Hook), false},
		{"ed subst write", raLin, `ed -s ` + r2Hook + ` <<< $',s/a/b/g\nw'`, r2Verdict("K|write:" + r2Hook), false},
		{"ed w other", raLin, "ed -s /home/u/proj/notes.txt <<'EOF'\nw " + r2Hook + "\nq\nEOF", r2Verdict("K|write:" + r2Hook), false},
		{"ed print", raLin, "ed -s " + r2Hook + " <<'EOF'\n,p\nq\nEOF", r2Verdict("K|"), false},
		{"ed stdin unknown", raLin, `ed -s ` + r2Hook, gap0506Unknown(), false},
		{"ed shell", raLin, `printf '!sh\n' | ed -s ` + r2Hook, gap0506Unknown(), false},
		{"ed global", raLin, `printf 'g/x/d\nw\n' | ed -s ` + r2Hook, gap0506Unknown(), false},
	})
}

// gap0506Unknown wants a call that is not fully known.
func gap0506Unknown() func(Result) string {
	return func(r Result) string {
		if r.FullyKnown() {
			return "fully known, want not fully known"
		}
		return ""
	}
}
