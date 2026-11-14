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
	// GAP-0522 recall guards: values that look like the benign shapes
	// below but hold a password are still reported.
	report = append(report,
		`password: "`+pw("Pass", "word2024!")+`"`,  // the key word inside one word
		`password = "my-`+pw("Wq7", "mz2")+`"`,     // a slug with digits
		`"password": "@`+pw("dm1n", "Pass")+`"`,    // a sigil and a word with a digit
		`password = "`+pw("Secret", "|2024x")+`"`,  // a pipe, not a rule list
		`password: "^`+pw("Wq7mz", "2Lp")+`"`,      // a caret, not a regex
		`"password": "**`+pw("Wq7m", "z2Lp")+`**"`, // stars around a password
		`"pwd": "`+pw("Wq7m", "/z2Lp!")+`"`,        // a slash, not a path
	)
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

// benignPasswordRows are the reviewer's benign probe rows (TestZZQrf2Benign,
// s7-respfrev) with the completion verdict rel a75abaec78 gave them. rel
// is the floor (GAP-0522): the pack rules report none of them on any
// surface, and the completion and prompt checks decide each row as rel
// did (rel's LP-SECRET list still alerts where it did).
var benignPasswordRows = []struct{ id, in, rel string }{
	{"B01", `'password' => 'required|string|min:8|confirmed',`, "allow"},
	{"B02", `password: 'required|min:8'`, "alert"},
	{"B03", `UPDATE users SET password = :password WHERE id = :id`, "alert"},
	{"B04", `"password": "{password}"`, "allow"},
	{"B05", `password="{db_password}"`, "alert"},
	{"B06", `"password": "[REDACTED]"`, "allow"},
	{"B07", `password=[REDACTED]`, "alert"},
	{"B08", `"password": "your-password-here"`, "allow"},
	{"B09", `DB_PASSWORD=your_db_password_here`, "allow"},
	{"B10", `password: your-password`, "alert"},
	{"B11", `/etc/passwd:root:x:0:0:root:/root:/bin/bash`, "alert"},
	{"B12", `pwd: "packages/core"`, "alert"},
	{"B13", `"password": "#{ENV[DB_PASS]}"`, "allow"},
	{"B14", `password = @Password`, "alert"},
	{"B16", `"password": "^(?=.*[A-Z])(?=.*[0-9]).{8,}$"`, "allow"},
	{"B17", `Password: must contain 8+ chars`, "allow"},
	{"B21", `"password": "Enter your password"`, "allow"},
	{"B23", `"password": "string"`, "allow"},
	{"B25", `"password": "env:DB_PASSWORD"`, "allow"},
	{"B27", `password=**redacted**`, "alert"},
	{"B29", `"password": "%(db_password)s"`, "allow"},
	{"B30", `"password": "$(DB_PASSWORD)"`, "allow"},
	{"B31", `password: <%= ENV.fetch("DB_PASSWORD") %>`, "allow"},
	{"B32", `{"token_type":"Bearer","expires_in":3600}`, "allow"},
	{"B33", `WWW-Authenticate: Bearer realm="api", error="invalid_token"`, "allow"},
	{"B35", `Bearer sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx`, "allow"},
	{"B37", `Bearer YOUR_ACCESS_TOKEN_GOES_HERE_1`, "alert"},
	{"B39", `password_confirmation: 'required|same:password'`, "allow"},
	{"B40", `"passwordPolicy": "min8-upper1-digit1"`, "allow"},
	{"B41", `PASSWORD_MIN_LENGTH=12 PASSWORD_REQUIRE_DIGIT=true`, "allow"},
	{"B42", `pwd=src/components/forms`, "alert"},
	{"B43", `$ echo PWD=packages/web-app`, "alert"},
	{"B44", `password: "Must be 8+ characters, 1 digit"`, "allow"},
	{"B45", `"pwd": "C:/Users/dev/proj"`, "allow"},
	{"B46", `password: ENC(AbC123xYz==)`, "alert"},
	{"B47", `password = request.form["password"]`, "alert"},
	{"B48", `password = req.body.password;`, "alert"},
	{"B49", `password: z.string().min(8)`, "alert"},
	{"B50", `"password": "********"`, "allow"},
	{"B51", `"password": "<PASSWORD>"`, "allow"},
	{"B52", `password: "{{ vault_db_password }}"`, "allow"},
	{"B53", `"password": "${{ secrets.DB_PASSWORD }}"`, "allow"},
	{"B54", `$table->string('password', 255);`, "allow"},
	{"B55", `'password' => Hash::make($request->password),`, "allow"},
	{"B56", `'password' => bcrypt('secret'),`, "allow"},
}

// TestPasswordBenignRowsKeepTheRelFloor (GAP-0522): no benign row is
// reported by SEC-PASSWORD-ASSIGN or SEC-BEARER-BARE, so no surface alerts
// on a row rel allows.
func TestPasswordBenignRowsKeepTheRelFloor(t *testing.T) {
	insp := NewGuardrailInspector("local", nil, nil)
	for _, row := range benignPasswordRows {
		for _, tool := range []string{"write_file", "send_message"} {
			findings := ScanAllRules(row.in, tool)
			if hasRule(findings, passwordAssignRuleID) || hasRule(findings, bareBearerRuleID) {
				t.Errorf("%s %s: reported by the pack: %q", row.id, tool, row.in)
			}
		}
		for _, direction := range []string{"completion", "prompt"} {
			v := insp.Inspect(context.Background(), direction, row.in, nil, "m", "action")
			if v.Action != row.rel {
				t.Errorf("%s %s: %s/%s, rel %s: %q %v", row.id, direction, v.Action, v.Severity, row.rel, row.in, v.Findings)
			}
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
	v8 := pw("Wq7m", "z2Lp")
	for _, in := range []string{
		`DB_PASSWORD=` + pw("Wq7m", "z2Lp9"),
		`Use Bearer ` + pw("q7Vx2M9p", "4Rk8T3n6", "W1y5Za0B") + ` here`,
		// GAP-0522: quoted keys, which only the pack rule reads.
		`"password": "` + v8 + `"`,
		`'password' => '` + v8 + `!',`,
		`"password": "svc.` + pw("Login", "99") + `"`,
	} {
		for _, direction := range []string{"completion", "prompt"} {
			v := insp.Inspect(context.Background(), direction, in, nil, "m", "action")
			if v.Severity == "NONE" || !strings.Contains(strings.Join(v.Findings, " "), "SEC-") {
				t.Errorf("%s %q: %+v", direction, in, v)
			}
		}
	}
}
