// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

// GAP-0371: a short password assignment and a bare Bearer credential are
// found by the rule pack on every surface, not only by the proxy's own list.
// GAP-0476: a quoted value is a literal, whatever it holds; only an
// unquoted identifier path is code.

// pw is a synthetic password assembled at run time.
func pw(parts ...string) string { return runtimeDetectorSignature(parts...) }

func hasRule(findings []RuleFinding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestPasswordAssignmentRule(t *testing.T) {
	v8 := pw("Wq7m", "z2Lp")  // 8 characters
	v9 := pw("Wq7#", "mz2Lp") // 9, with a symbol
	report := []string{
		`password = "` + v9 + `"`,
		`DB_PASSWORD=` + v8 + `9`,
		`"password": "` + v8 + `"`,
		`{\"db_password\": \"` + v8 + `\"}`,
		`userPwd: '` + v8 + `!'`,
		`passwd => "` + v8 + `"`,
		`password := "` + v8 + `"`,
		`mysql --password=` + v8,
		`export MYSQL_PWD=` + v8,
		`PGPASSWORD=` + v8 + ` psql -h db`,
		`passphrase: ` + v9,
		// GAP-0476: quoted dotted literals are passwords.
		`password = "admin.` + pw("Secret", "2024") + `"`,
		`password: 'corp.` + pw("Pass", "2024") + `'`,
		`"password": "svc.` + pw("Login", "99") + `"`,
		`PASSWORD="ops.` + pw("Deploy", "7") + `"`,
		`{\"password\": \"db.` + pw("Main", "2026") + `\"}`,
	}
	ignore := []string{
		// Code: an unquoted identifier path, or a call or index on a name.
		`password = opts.Password`,
		`password: config.ReadPassword()`,
		`pwd = flags.AdminPassword`,
		`password = os.environ.get("DB_PASSWORD")`,
		`password: Optional[str] = None`,
		`password = getpass()`,
		`password = self->secret_pw`,
		`password = Settings::AdminPw`,
		// References and template slots.
		`password = ${DB_PASSWORD}`,
		`password=$DB_PASSWORD_VALUE`,
		`set password=%DB_PASSWORD%`,
		`password: <your-password>`,
		// Words, placeholders, paths, prose.
		`password: required`,
		`password = None`,
		`password: changeme`,
		`password = "********"`,
		`password: xxxxxxxxxx`,
		`pwd: /home/user/project`,
		`password: https://vault.example/x`,
		`the password is required for login`,
		// The key must end on its password word.
		`password_hash = ` + v9,
		`passwordReset: ` + v9,
		`password_min_length: 12345678`,
		`password: Ab1`, // too short
	}
	for _, in := range report {
		if !hasRule(ScanAllRules(in, "write_file"), passwordAssignRuleID) {
			t.Errorf("not reported: %q", in)
		}
	}
	for _, in := range ignore {
		if hasRule(ScanAllRules(in, "write_file"), passwordAssignRuleID) {
			t.Errorf("reported: %q", in)
		}
	}
}

func TestBareBearerRule(t *testing.T) {
	tok := pw("q7Vx2M9p", "4Rk8T3n6", "W1y5Za0B")
	report := []string{
		`Use Bearer ` + tok + ` for the call`,
		`curl -H "X-Api-Token: Bearer ` + tok + `"`,
		`{"Authorization": "Bearer ` + tok + `"}`,
	}
	ignore := []string{
		`Authorization: Bearer ` + tok, // SEC-BEARER reports the header form
		`bearer: Bearer ` + tok,
		`Bearer authentication_and_authorization_flow`,
		`Bearer xxxxxxxxxxxxxxxxxxxxxxxx1`,
		`Bearer ${ACCESS_TOKEN}`,
		`Bearer <access-token>`,
	}
	for _, in := range report {
		if !hasRule(ScanAllRules(in, "send_message"), bareBearerRuleID) {
			t.Errorf("not reported: %q", in)
		}
	}
	for _, in := range ignore {
		if hasRule(ScanAllRules(in, "send_message"), bareBearerRuleID) {
			t.Errorf("reported: %q", in)
		}
	}
	if !hasRule(ScanAllRules(`Authorization: Bearer `+tok, "send_message"), "SEC-BEARER") {
		t.Errorf("SEC-BEARER no longer reports the header form")
	}
}

// TestPasswordAndBearerOnEverySurface: the completion check and the prompt
// check find both shapes, as the tool-call scan above does.
func TestPasswordAndBearerOnEverySurface(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	for _, in := range []string{
		`DB_PASSWORD=` + pw("Wq7m", "z2Lp9"),
		`Use Bearer ` + pw("q7Vx2M9p", "4Rk8T3n6", "W1y5Za0B") + ` here`,
	} {
		for _, direction := range []string{"completion", "prompt"} {
			v := insp.Inspect(context.Background(), direction, in, nil, "m", "action")
			if v.Severity == "NONE" || !strings.Contains(strings.Join(v.Findings, " "), "SEC-") {
				t.Errorf("%s %q: %+v", direction, in, v)
			}
		}
	}
}
