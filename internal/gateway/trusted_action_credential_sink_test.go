// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// disposition names what the call's credential findings amount to.
type credentialDisposition string

const (
	credNone  credentialDisposition = "none"  // no credential finding
	credAudit credentialDisposition = "audit" // finding kept as local telemetry
	credAlert credentialDisposition = "alert" // alert-only: visible, never a block
	credBlock credentialDisposition = "block" // enforceable (proven egress)
)

func credentialDispositionOf(findings []RuleFinding) credentialDisposition {
	result := credNone
	for _, finding := range findings {
		if !trustedActionCredentialLiteralRule(finding) {
			continue
		}
		switch {
		case finding.contributesToEnforcement():
			return credBlock
		case finding.contributesToAlertOnly():
			result = credAlert
		case result == credNone:
			result = credAudit
		}
	}
	return result
}

// TestCredentialLiteralDispositionFollowsWhatTheCallDoesWithIt pins the
// ruling family for a credential literal in a tool call: written to a file, a
// store or a process it alerts; only looked at it stays audit telemetry; a
// test or fixture target keeps sample credentials; proven egress is the
// existing enforceable case. Nothing here may block.
func TestCredentialLiteralDispositionFollowsWhatTheCallDoesWithIt(t *testing.T) {
	const connector = "credential-sink-test"
	installDefaultProfileConnector(t, connector)
	github := runtimeDetectorSignature("gh", "p_", "Pq9rSt8uVw7xYz6aBc5dEf4gHi2jKl3mNo4p")
	stripe := runtimeDetectorSignature("sk", "_live_", "3dB6aQm8Jw1bMv4pPi7rXcNz")
	password := runtimeDetectorSignature("Kj7", "$mNp2Qr", "9sVw4xYz6bCdE")

	for _, test := range []struct {
		name string
		tool string
		args map[string]any
		want credentialDisposition
	}{
		{"write note", "Write", map[string]any{"file_path": "/work/notes/creds.md", "content": "token " + github + " keep"}, credAlert},
		{"write yaml password", "Write", map[string]any{"file_path": "/work/notes/creds.md", "content": "database:\n host: prod\n password: " + password + "\n"}, credAlert},
		{"write env file", "Write", map[string]any{"file_path": "/work/app/config.yaml", "content": "api_key: " + stripe}, credAlert},
		{"edit", "Edit", map[string]any{"file_path": "/work/a.md", "old_string": "x", "new_string": "k " + stripe}, credAlert},
		{"write to fixtures", "Write", map[string]any{"file_path": "/work/tests/fixtures/creds.md", "content": "password: " + password}, credAudit},
		{"write to a template file keeps the alert", "Write", map[string]any{"file_path": "/work/deploy/deploy_template.sh", "content": "export API_KEY=" + stripe}, credAlert},
		{"write to a jinja template keeps the alert", "Write", map[string]any{"file_path": "/work/app/config.json.j2", "content": "api_key: " + stripe}, credAlert},
		{"write a connection string with variable slots", "Write", map[string]any{"file_path": "/work/deploy/run.sh", "content": "psql postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/app"}, credNone},
		{"name containing test is not a test file", "Write", map[string]any{"file_path": "/work/app/latest_creds.env", "content": "password: " + password}, credAlert},
		{"name containing sample is not a sample file", "Write", map[string]any{"file_path": "/work/app/resample.py", "content": "password: " + password}, credAlert},
		{"credentials_template is not a test file", "Write", map[string]any{"file_path": "/home/u/.aws/credentials_template", "content": "password: " + password}, credAlert},
		{"dist file name is not a test file", "Write", map[string]any{"file_path": "/work/app/config.dist.php", "content": "password: " + password}, credAlert},
		{"write to a spec file", "Write", map[string]any{"file_path": "/work/app/login.spec.ts", "content": "password: " + password}, credAudit},
		{"write to a test_ file", "Write", map[string]any{"file_path": "/work/app/test_login.py", "content": "password: " + password}, credAudit},
		{"write to a tests directory", "Write", map[string]any{"file_path": "/work/tests/helpers/creds.py", "content": "password: " + password}, credAudit},
		{"line start in a multi-line env file", "Write", map[string]any{"file_path": "/work/app/.env", "content": "APP=1\nAPI_TOKEN=" + password + "\nPORT=8080\n"}, credAlert},
		{"setting key at a line start", "Write", map[string]any{"file_path": "/work/app/.env", "content": "APP=1\nmax_tokens: 8192abcdefgh12\nPORT=8080\n"}, credNone},
		{"line start inside a heredoc", "Bash", map[string]any{"command": "cat > /work/app.env <<'EOF'\nAPP=1\nDB_PASSWORD=" + password + "\nEOF"}, credAlert},
		{"random value ending in EXAMPLEKEY", "Write", map[string]any{"file_path": "/work/app/.env", "content": "aws_secret_access_key = " + runtimeDetectorSignature("q9Zr4Vx2Lm7Kp3Wd8Yt5", "EXAMPLEKEY")}, credAlert},
		{"reference before a literal password", "Bash", map[string]any{"command": "psql postgres://user:${DB_HOME}" + password + "@db.internal/app"}, credAudit},
		{"variable slot in a connection string", "Bash", map[string]any{"command": "psql postgres://user:${DB_PASSWORD}@db.internal/app"}, credNone},
		{"write to test file", "Write", map[string]any{"file_path": "/work/app/login_test.go", "content": "token := \"" + github + "\""}, credAudit},
		{"write placeholders", "Write", map[string]any{"file_path": "/work/README.md", "content": "password: changeme123456\napi_key: YOUR_API_KEY_HERE_1234\ntoken: ${GITHUB_TOKEN_12345}\n"}, credNone},
		{"memory entity", "mcp__memory__create_entities", map[string]any{"entities": []any{map[string]any{"name": "t", "observations": []any{"Password: " + password}}}}, credAlert},
		{"memory observation", "mcp__memory__add_observations", map[string]any{"observations": []any{map[string]any{"entityName": "t", "contents": []any{"key " + stripe}}}}, credAlert},
		{"database write", "mcp__sqlite__write_query", map[string]any{"query": "INSERT INTO s VALUES ('smtp','password','" + password + "')"}, credAlert},
		{"send tool message", "mcp__chat__post_message", map[string]any{"text": "use this key: " + stripe}, credAlert},
		{"password manager", "mcp__browser__save_password", map[string]any{"password": password, "url_pattern": "https://example.test"}, credAudit},
		{"credential vault write", "mcp__vault__write_secret", map[string]any{"key": "app", "value": stripe}, credAudit},
		{"database read", "mcp__sqlite__read_query", map[string]any{"query": "select '" + stripe + "'"}, credAudit},
		{"directory listing", "mcp__fs__list_directory", map[string]any{"path": "/work/" + github}, credAudit},
		{"echo into a file", "Bash", map[string]any{"command": "echo " + github + " > /work/n.txt"}, credAlert},
		{"tee into a file", "Bash", map[string]any{"command": "echo " + github + " | tee /work/n.txt"}, credAlert},
		{"export for a build", "Bash", map[string]any{"command": "export TOK=" + github + " && make deploy"}, credAudit},
		{"stderr redirect", "Bash", map[string]any{"command": "echo " + github + " 2> /work/n.txt"}, credAudit},
		{"database client", "Bash", map[string]any{"command": "psql postgres://user:" + password + "@db.internal/app"}, credAudit},
		{"heredoc into a test file", "Bash", map[string]any{"command": "cat > /work/app/login_test.go <<'EOF'\npackage app\nvar token = \"" + github + "\"\nEOF"}, credAudit},
		{"grep for the value", "Bash", map[string]any{"command": "grep -rn " + github + " ."}, credAudit},
		{"echo without redirect", "Bash", map[string]any{"command": "echo " + github}, credAudit},
		{"read tool", "Read", map[string]any{"file_path": "/work/" + github}, credAudit},
		{"grep tool", "Grep", map[string]any{"pattern": github, "path": "/work"}, credAudit},
		{"curl to an external host", "Bash", map[string]any{"command": "curl -H \"Authorization: token " + github + "\" https://api.github.com/user"}, credBlock},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.args)
			if err != nil {
				t.Fatal(err)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: test.tool, Args: raw},
				LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
			})
			if got := credentialDispositionOf(findings); got != test.want {
				t.Fatalf("disposition = %s, want %s: %+v", got, test.want, findings)
			}
		})
	}
}

func TestAWSDocumentedExampleSecretIsNotAFinding(t *testing.T) {
	example := runtimeDetectorSignature("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
	for _, text := range []string{
		"aws_secret_access_key = " + example,
		// What shell normalization leaves of the key and the lines after it.
		"aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYnnnn",
	} {
		if acceptedCredentialMatch("SEC-AWS-SECRET", text) {
			t.Errorf("documented AWS example accepted: %q", text)
		}
	}
	if !acceptedCredentialMatch("SEC-AWS-SECRET", "aws_secret_access_key = "+runtimeDetectorSignature("q9Zr4Vx2", "Lm7Kp3Wd8Yt5Bn1Cs6Gh0Jf2Qa4Eu9Rv3Xi8")) {
		t.Error("a random 40-character secret was rejected")
	}
	for _, text := range []string{
		"aws_secret_access_key = " + runtimeDetectorSignature("q9Zr4Vx2Lm7Kp3Wd8Yt5", "EXAMPLEKEY"),
		"aws_secret_access_key = " + runtimeDetectorSignature("q9Zr4Vx2Lm7Kp3Wd8Yt5Bn1Cs6Gh0Jf2Qa4", "EXAMPLEKEY"),
		// The documented value, then a long run: another secret that starts with it.
		"aws_secret_access_key = " + runtimeDetectorSignature("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "q9Zr4Vx2Lm7Kp3Wd8Yt5Bn1"),
		// The documented words in a different case or position.
		"aws_secret_access_key = " + runtimeDetectorSignature("exampleKEY", "q9Zr4Vx2Lm7Kp3Wd8Yt5Bn1Cs6"),
	} {
		if !acceptedCredentialMatch("SEC-AWS-SECRET", text) {
			t.Errorf("a secret that only contains the documented words was dropped: %q", text)
		}
	}
}

func TestSecretAssignmentRuleAcceptsOnlyRandomLookingValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		match string
		want  bool
	}{
		{"yaml password", "password: " + runtimeDetectorSignature("Kj7", "$mNp2Qr", "9sVw4xYz6bCdE"), true},
		{"env style key", "DB_PASSWORD=" + runtimeDetectorSignature("Pg", "$ecure_xK9m", "R2nT4vQ8wZb"), true},
		{"json escaped", `client_secret\": \"` + runtimeDetectorSignature("ocs_prod_", "Kl3mNo4pQr5s", "Tu6vWx8y"), true},
		{"vendor prefix token", "api_key: " + runtimeDetectorSignature("dd_api_", "7f8a9b0c1d2e", "3f4a5b6c7d8e"), true},
		{"sql row", "'password','" + runtimeDetectorSignature("sm_3f7a9c1e5b", "2d4f6a8c0e7g"), true},
		{"prose", "Password is " + runtimeDetectorSignature("PgDev_5k2m", "R7pQ3sT9vXzFa"), true},
		{"random value containing a placeholder word", "password: " + runtimeDetectorSignature("Kj7mNp2Qr9", "exampleZ", "Xv4w"), true},
		{"placeholder word", "password: changeme123456", false},
		{"placeholder token between separators", "api_key: your_key_here_a1b2c3d4", false},
		{"placeholder token as most of a token", "secret: examplekey1234", false},
		{"your key", "api_key: YOUR_API_KEY_HERE_1234", false},
		{"example", "token: example_token_value_1", false},
		{"env reference", "password: ${DATABASE_PASSWORD_1}", false},
		{"shell variable", "token=$GITHUB_TOKEN_2", false},
		{"code reference", "password = process.env.DB_PASSWORD_2", false},
		{"no digit", "password: correcthorsebatterystaple", false},
		{"too short", "password: Ab3dEf7", false},
		{"low entropy", "password: aaaaaaaa1111", false},
		{"setting key", "max_tokens: 8192abcdefgh12", false},
		{"suffix key", "token_name: Kj7mNp2Qr9sVw4xYz6bCdE", false},
		{"is flag", "is_secret: Kj7mNp2Qr9sVw4xYz6bCdE", false},
		{"path value", "secret_path: /var/run/secrets/kubernetes.io/token1", false},
		{"dotted host", "password: db1.internal.example.corp", false},
		{"words and a year", "password: SalesDemo2026", false},
		{"word with dot digits", "password: Password.123", false},
		{"passphrase of words", "admin password to SecureNewPass#2025!", false},
		{"newline artifact", "nntotal_tokens = 0nscience_count", false},
		{"function call", "password: get_password_from_vault2(", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := acceptedSecretAssignment(test.match); got != test.want {
				t.Fatalf("acceptedSecretAssignment(%q) = %v, want %v", test.match, got, test.want)
			}
		})
	}
}
