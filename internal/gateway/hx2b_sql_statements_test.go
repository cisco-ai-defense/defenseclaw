// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type hx2bVerdict struct {
	action string
	rules  []string
}

// hx2bTierVerdicts judges each command as a Codex Bash call in the five
// tiers (default, permissive, strict, managed, managed-strict).
func hx2bTierVerdicts(t *testing.T, commands []string) map[string][]hx2bVerdict {
	t.Helper()
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	t.Setenv("HOME", home)
	const connector = "codex"
	out := map[string][]hx2bVerdict{}
	calls := 0
	for _, tier := range []struct {
		name, posture string
		managed       bool
	}{
		{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false},
		{"managed", "default", true}, {"managed-strict", "strict", true},
	} {
		installToolCallCorpusProfileConnector(t, connector, tier.posture)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.posture)
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		ctx := context.Background()
		if tier.managed {
			ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		}
		hook := hookRuntimeForProfile(api.hookProfileForRequest(ctx, connector))
		for _, command := range commands {
			calls++
			id := "hx2b-" + strconv.Itoa(calls)
			args, _ := json.Marshal(map[string]string{"command": command})
			raw, _ := json.Marshal(map[string]any{
				"session_id": id, "turn_id": "turn-1", "hook_event_name": "PreToolUse", "cwd": cwd,
				"model": "fixture-model", "tool_name": "Bash", "tool_use_id": "call-" + id,
				"tool_input": map[string]any{"command": command},
			})
			var payload map[string]interface{}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			resp, panicked := api.safeEvaluateHook(ctx, connector, agentHookRequest{
				ConnectorName: connector, CWD: cwd, HookEventName: "PreToolUse",
				ToolName: "Bash", ToolArgs: args,
			}, raw, payload, hook)
			if panicked {
				t.Fatalf("%s %.80q: hook evaluator panicked", tier.name, command)
			}
			var rules []string
			for _, finding := range resp.Findings {
				id, _, _ := strings.Cut(finding, ":")
				if id != "ACTION-COMPOUND-LIMIT" {
					rules = append(rules, id)
				}
			}
			out[tier.name] = append(out[tier.name], hx2bVerdict{resp.Action, rules})
		}
	}
	return out
}

func hx2bQuote(s string) string { return "\x27" + s + "\x27" }

// hx2bLongSelects is a benign prefix of SELECT statements past the 4 KiB
// shell word bound.
var hx2bLongSelects = strings.Repeat("SELECT 1; ", 500)

// hx2bLongLiteral is a benign statement whose literal is past the bound.
var hx2bLongLiteral = "SELECT " + hx2bQuote(strings.Repeat("a", 5000)) + " AS note; "

// hx2bSameAsBare asserts every form gets, in every tier, the action of the
// bare statement and its rules.
func hx2bSameAsBare(t *testing.T, bare string, forms []string) {
	t.Helper()
	verdicts := hx2bTierVerdicts(t, append([]string{bare}, forms...))
	for tier, rows := range verdicts {
		want := rows[0]
		if len(want.rules) == 0 {
			t.Fatalf("%s: bare %q raises nothing; the premise is broken", tier, bare)
		}
		for i, got := range rows[1:] {
			if got.action != want.action || !hx2bContainsAll(got.rules, want.rules) {
				t.Errorf("%s: %.160q gives %s %v, want %s %v as the bare statement", tier, forms[i], got.action, got.rules, want.action, want.rules)
			}
		}
	}
}

func hx2bContainsAll(have, want []string) bool {
	for _, id := range want {
		if !slices.Contains(have, id) {
			return false
		}
	}
	return true
}

// rel-1-0-10:GAP-1926 (DET111 ruling B): each statement of a multi-statement
// inline query (psql -c, mysql -e, sqlcmd -Q/-q, snowsql -q; short and long
// options) is read as its own exact candidate and decided as its bare form,
// never above: after a SELECT, before one, inside BEGIN ... COMMIT, and past
// the 4 KiB word bound (the chunked reading under the per-call budget).
func TestGAP1926MultiStatementQueryReadsEachStatement(t *testing.T) {
	for _, row := range []struct {
		client, long, statement string
	}{
		{"psql -d production -c", "psql -d production --command=", "DROP DATABASE production"},
		{"psql -d production -c", "psql -d production --command=", "DROP TABLE users"},
		{"psql -d production -c", "psql -d production --command=", "COPY t (c) TO PROGRAM " + hx2bQuote("id")},
		{"psql -d production -c", "psql -d production --command=", "SELECT pg_read_file(" + hx2bQuote("/etc/shadow") + ")"},
		{"mysql -h db -e", "mysql -h db --execute=", "SELECT LOAD_FILE(" + hx2bQuote("/etc/shadow") + ")"},
		{"mysql -h db -e", "mysql -h db --execute=", "DROP DATABASE production"},
		{"sqlcmd -S db -Q", "sqlcmd -S db -q", "DROP TABLE users"},
		{"snowsql -q", "snowsql --query=", "DROP DATABASE production"},
	} {
		t.Run(row.statement, func(t *testing.T) {
			s := row.statement
			queries := []string{
				"SELECT 1; " + s,
				s + "; SELECT 1",
				"SELECT 1; " + s + "; SELECT 2;",
				"BEGIN; SELECT 1; " + s + "; COMMIT",
				hx2bLongSelects + s,
				hx2bLongLiteral + s + ";",
			}
			var forms []string
			for _, q := range queries {
				forms = append(forms, row.client+" \""+q+"\"")
				if strings.HasSuffix(row.long, "=") {
					forms = append(forms, row.long+"\""+q+"\"")
				} else {
					forms = append(forms, row.long+" \""+q+"\"")
				}
			}
			hx2bSameAsBare(t, row.client+" \""+s+"\"", forms)
		})
	}
}

// rel-1-0-10:GAP-1926: a mutation inside a transaction the query rolls back
// changes no data and stays unread (the 1.0.10 cell); a server program or
// file read inside it runs all the same and is read; MySQL commits before a
// DROP, so a DROP inside BEGIN ... ROLLBACK is read.
func TestGAP1926RolledBackStatements(t *testing.T) {
	rolledBack := []string{
		"psql -d production -c \"BEGIN; SELECT 1; DELETE FROM customers; ROLLBACK\"",
		"psql -d production -c \"BEGIN; DROP TABLE users; SELECT 1; ROLLBACK; SELECT 2\"",
		"psql -d production -c \"BEGIN; SELECT 1; DROP TABLE users\"",
	}
	verdicts := hx2bTierVerdicts(t, rolledBack)
	for tier, rows := range verdicts {
		for i, got := range rows {
			if got.action != "allow" || len(got.rules) != 0 {
				t.Errorf("%s: %q gives %s %v, want allow with no finding (rolled back)", tier, rolledBack[i], got.action, got.rules)
			}
		}
	}
	hx2bSameAsBare(t, "psql -d production -c \"COPY t (c) TO PROGRAM "+hx2bQuote("id")+"\"", []string{
		"psql -d production -c \"BEGIN; SELECT 1; COPY t (c) TO PROGRAM " + hx2bQuote("id") + "; ROLLBACK\"",
	})
	hx2bSameAsBare(t, "mysql -h db -e \"DROP TABLE users\"", []string{
		"mysql -h db -e \"BEGIN; SELECT 1; DROP TABLE users; ROLLBACK\"",
	})
}

// rel-1-0-10:GAP-1926: benign multi-statement queries (migrations, seeds,
// several SELECTs, long and short) raise nothing; statements past the
// per-call budget are not read and the cut raises nothing.
func TestGAP1926BenignMultiStatementAndBudget(t *testing.T) {
	stmt := "SELECT " + strings.TrimSuffix(strings.Repeat("1,", 1050), ",") + "; "
	benign := []string{
		"psql -d app -c \"BEGIN; CREATE TABLE IF NOT EXISTS t (id int); INSERT INTO t VALUES (1); COMMIT\"",
		"psql -d app -c \"BEGIN; ALTER TABLE users ADD COLUMN note text; UPDATE users SET note = " + hx2bQuote("x") + " WHERE id = 1; COMMIT;\"",
		"mysql -h db -e \"SELECT 1; SELECT COUNT(*) FROM users; SHOW TABLES\"",
		"mysql -h db -e \"USE app; INSERT INTO seed (k) VALUES (1), (2); SELECT * FROM seed\"",
		"sqlcmd -S db -Q \"SELECT name FROM sys.tables; SELECT 1\"",
		"snowsql -q \"USE WAREHOUSE w; SELECT 1; SELECT 2\"",
		"psql -d app -c \"" + hx2bLongSelects + "SELECT 2\"",
		"mysql -h db -e \"" + hx2bLongLiteral + "SELECT 2;\"",
		// 30 statements of 2 KiB: one per chunk, past the budget of 16
		// readings; the DROP at the end is not read.
		"psql -d production -c \"" + strings.Repeat(stmt, 30) + "DROP TABLE users\"",
	}
	verdicts := hx2bTierVerdicts(t, benign)
	for tier, rows := range verdicts {
		for i, got := range rows {
			if got.action != "allow" || len(got.rules) != 0 {
				t.Errorf("%s: %.160q gives %s %v, want allow with no finding", tier, benign[i], got.action, got.rules)
			}
		}
	}
}

// rel-1-0-10:GAP-1961: LOAD_FILE (and pg_read_file) of a closed sensitive
// path as any item of a literal SELECT is the sensitive server file read of
// the one-item query, short and long form; a non-sensitive path stays
// without the rule.
func TestGAP1961FileReadAsAnySelectItem(t *testing.T) {
	load := "LOAD_FILE(" + hx2bQuote("/etc/shadow") + ")"
	hx2bSameAsBare(t, "mysql -h db -e \"SELECT "+load+"\"", []string{
		"mysql -h db -e \"SELECT " + load + ", 1\"",
		"mysql -h db -e \"SELECT " + load + " AS a, 2 AS b\"",
		"mysql -h db -e \"SELECT 1, " + load + "\"",
		"mysql -h db -e \"SELECT CONCAT(" + hx2bQuote("a,b") + ", 1), " + load + " AS a;\"",
		"mysql -h db --execute=\"" + hx2bLongSelects + "SELECT " + load + " AS a, 2 AS b\"",
	})
	pg := "pg_read_file(" + hx2bQuote("/etc/shadow") + ")"
	hx2bSameAsBare(t, "psql -d production -c \"SELECT "+pg+"\"", []string{
		"psql -d production -c \"SELECT " + pg + " AS a, 1 AS b\"",
	})
	other := []string{
		"mysql -h db -e \"SELECT LOAD_FILE(" + hx2bQuote("/tmp/report.txt") + "), 1\"",
		"mysql -h db -e \"SELECT 1, 2\"",
	}
	for tier, rows := range hx2bTierVerdicts(t, other) {
		for i, got := range rows {
			if got.action != "allow" || len(got.rules) != 0 {
				t.Errorf("%s: %q gives %s %v, want allow with no finding", tier, other[i], got.action, got.rules)
			}
		}
	}
}
