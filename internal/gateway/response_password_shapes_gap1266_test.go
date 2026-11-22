// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// Review r2 of GAP-0210 (s7-rv0210) rows. The base column is rel/1.0.10
// da4177e225 with each pack's posture thresholds (SetPosture): its proxy
// password regex, (?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,},
// took any value of eight characters, on the line after the key too.
var gap1266Rows = map[string]string{
	"N01": "password=12345678",
	"N02": "password=20240101",
	"N03": "pwd=87654321",
	"N04": "password=!@#$%^&*",
	"N05": "password=1234-5678",
	"N06": "passcode password: 99887766",
	"W12": "password:\n  changeme123",
	"W13": "password=`changeme123`",
	"W33": "password=pass,word123",
	"S01": "password=" + pw("Hunter2", "!xQ"),
	"S02": "password=`" + pw("Hunter2", "!xQ") + "`",
	"S03": "password:\n  " + pw("Hunter2", "!xQ"),
	"S04": "password=" + pw("Hunt,er2", "!xQzz"),
	"R01": "password=password123",
	"R02": "password=changeme123",
	"R03": "password=dummysecret",
	"R04": "password=examplepass",
	"W01": "PASSWORD=changeme123",
	"I01": "password\u200b=changeme123",
}

// gap1266WantAtLeast runs rows bare and in the middle of an assistant turn
// through the proxy content check with each tier's posture and fails when
// the action is weaker than want (base's action for that posture). Surfaces:
// a whole completion and a streamed one (regex_only), and a proxy prompt with
// the default strategy regex_judge. No verdict carries the value.
func gap1266WantAtLeast(t *testing.T, ids, surfaces []string, want map[string]string) {
	t.Helper()
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	for _, tier := range gap0210WeakPasswordTiers {
		w, ok := want[tier.name]
		if !ok {
			continue
		}
		ctx := tier.context(t)
		only := tier.inspector()
		rj := NewGuardrailInspector("local", nil, nil)
		rj.SetDetectionStrategy("regex_judge", "", "", "", false)
		rj.SetPosture(tier.pack)
		for _, id := range ids {
			row, ok := gap1266Rows[id]
			if !ok {
				t.Fatalf("no row %s", id)
			}
			for _, where := range []string{"bare", "middle"} {
				text := row
				if where == "middle" {
					text = gap0210Turn(row, "middle")
				}
				for _, s := range surfaces {
					var v *ScanVerdict
					switch s {
					case "completion":
						v = only.Inspect(ctx, "completion", text, nil, "model", "action")
					case "stream":
						streamed := gap0210Stream(ctx, only, text)
						v = streamed[len(streamed)-1]
					case "prompt-rj":
						v = rj.Inspect(ctx, "prompt", text, []ChatMessage{{Role: "user", Content: text}}, "model", "action")
					}
					if rank[v.Action] < rank[w] {
						t.Errorf("%s %s %s %s: %s %s %v, base had %s", tier.name, id, where, s, v.Action, v.Severity, v.Findings, w)
					}
					trimmed := strings.TrimRight(row, "`")
					value := trimmed[strings.LastIndexAny(trimmed, "=: \n`")+1:]
					for _, f := range append(append([]string{}, v.Findings...), v.Reason) {
						if len(value) >= 8 && strings.Contains(f, value) {
							t.Errorf("%s %s %s %s: verdict carries the value", tier.name, id, where, s)
						}
					}
				}
			}
		}
	}
}

var gap1266BaseActions = map[string]string{"default": "alert", "strict": "block", "managed": "alert", "managed-strict": "block"}

// TestGAP1266NumericOrSymbolPasswordStillAlerts: a value of digits or symbols
// only on a bare password key (a PIN, a date, a symbol run) is a weak
// password, not "none": the proxy reports it as rel did.
func TestGAP1266NumericOrSymbolPasswordStillAlerts(t *testing.T) {
	gap1266WantAtLeast(t, []string{"N01", "N02", "N03", "N04", "N05", "N06"}, []string{"completion", "stream", "prompt-rj"}, gap1266BaseActions)
}

// TestGAP1267BacktickPasswordStillAlerts: a value in markdown inline-code
// backticks, weak and strong.
func TestGAP1267BacktickPasswordStillAlerts(t *testing.T) {
	gap1266WantAtLeast(t, []string{"W13", "S02"}, []string{"completion", "stream", "prompt-rj"}, gap1266BaseActions)
}

// TestGAP1268NextLineOrCommaPasswordStillAlerts: a value on the line after
// the key (YAML) and a value with a comma in it, weak and strong.
func TestGAP1268NextLineOrCommaPasswordStillAlerts(t *testing.T) {
	gap1266WantAtLeast(t, []string{"W12", "S03", "W33", "S04"}, []string{"completion", "stream", "prompt-rj"}, gap1266BaseActions)
}

// TestGAP1268WiderValueReadingStaysQuietOnBenignText: the next-line,
// backtick, comma and digits-only readings do not reach text that is not a
// password: a YAML schema or a nested map under a password key, a sentence on
// the next line, a field list, a mask or a ruled line, code in backticks, a
// reference, a path. Neither the rule (every surface) nor the proxy content
// check of any tier reports them.
func TestGAP1268WiderValueReadingStaysQuietOnBenignText(t *testing.T) {
	quiet := []string{
		"password:\n  description: The login password\n  type: string",
		"password:\n  type: string\n  minLength: 8",
		"Password:\nEnter the password you chose at sign-up.",
		"password:\n  - required\n  - min:8",
		"password:\n  !vault |\n    6638643965",
		"login(user, password=pw,timeout=30)",
		"password=********",
		"password=--------",
		"password: ========",
		"password: `<your-password>`",
		"password: `opts.Password`",
		"password=`${DB_PASSWORD}`",
		"Use `--password=<value>` to pass it on the command line.",
		"pwd:\n/home/user/project",
		"password: required|min:8,max:64",
		"if password == stored_password:",
		"    if password != user.password:",
	}
	for _, in := range quiet {
		for _, tool := range []string{"write_file", "send_message"} {
			if hasRule(ScanAllRules(in, tool), passwordAssignRuleID) {
				t.Errorf("%s: reported by the pack: %q", tool, in)
			}
		}
	}
	for _, tier := range gap0210WeakPasswordTiers {
		ctx := tier.context(t)
		insp := tier.inspector()
		for _, in := range quiet {
			for _, text := range []string{in, gap0210Turn(in, "middle")} {
				if v := insp.Inspect(ctx, "completion", text, nil, "model", "action"); gap0210HasRule(v.Findings, passwordAssignRuleID) {
					t.Errorf("%s %q: completion %s %s %v, want quiet", tier.name, in, v.Action, v.Severity, v.Findings)
				}
			}
		}
	}
}
