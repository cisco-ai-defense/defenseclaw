// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// substrate-1:GAP-0532. SEC-AWS-SECRET read only an unquoted
// aws_secret_access_key = <value> assignment. A secret access key typed in a
// prompt next to its key id ("the secret is ..."), or returned the way the
// AWS CLI and SDK configs write it ("SecretAccessKey": "...", a quoted
// value, a CSV credentials row), raised no SEC-AWS-SECRET finding on the
// laptop or the actor. The fixtures are split so no scanner reads a key
// pair in this file; the 40-character values are random, not AWS keys.
var (
	gap0532KeyID         = runtimeDetectorSignature("AKIA", "3FKJ2M5NQ7XZ8BWV")
	gap0532SessionKeyID  = runtimeDetectorSignature("ASIA", "Q4M7XK2PZ9RT6WNB")
	gap0532Secret        = runtimeDetectorSignature("q9Zr4Vx2", "Lm7Kp3Wd8Yt5Bn1Cs6Gh0Jf2Qa4Eu9Rv")
	gap0532DocKeyID      = runtimeDetectorSignature("AKIA", "IOSFODNN7EXAMPLE")
	gap0532DocSecret     = runtimeDetectorSignature("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
	gap0532Unanchored    = runtimeDetectorSignature("Zt8Kq2Lw", "9Xv4Nb7Rc1Ms6Pd3Hf5Jg0Ya2Ue8Wi4O")
	gap0532CommitSHA1Hex = "3f786850e387550fdab836ed7e6dc881de23001b"
)

func hasRuleFindingGAP0532(findings []string, ruleID string) bool {
	for _, finding := range findings {
		if finding == ruleID || strings.HasPrefix(finding, ruleID+":") {
			return true
		}
	}
	return false
}

func scanHasRuleGAP0532(text, ruleID string) bool {
	for _, finding := range ScanAllRules(text, "unknown_tool") {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func gap0532ClaudeCodeAPI() *APIServer {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	return &APIServer{scannerCfg: cfg}
}

func TestGAP0532FixturesAreFortyCharacterSecrets(t *testing.T) {
	for name, value := range map[string]string{
		"secret": gap0532Secret, "documented": gap0532DocSecret,
		"unanchored": gap0532Unanchored, "sha1": gap0532CommitSHA1Hex,
	} {
		if len(value) != 40 {
			t.Fatalf("%s fixture is %d characters, want 40", name, len(value))
		}
	}
}

// A non-placeholder key pair typed in a UserPromptSubmit prompt is a
// SEC-AWS-SECRET finding as well as a SEC-AWS-KEY finding. At the base
// commit only SEC-AWS-KEY fired: the secret had no key name before it.
func TestClaudeCodePromptAWSKeyPairIsASecretFindingGAP0532(t *testing.T) {
	api := gap0532ClaudeCodeAPI()
	prompt := "My AWS key is " + gap0532KeyID + " and the secret is " + gap0532Secret + ". Remember them."
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        prompt,
	})
	for _, rule := range []string{"SEC-AWS-KEY", "SEC-AWS-SECRET"} {
		if !hasRuleFindingGAP0532(resp.Findings, rule) {
			t.Errorf("prompt findings = %v, want %s", resp.Findings, rule)
		}
	}
	if strings.Contains(resp.Reason, gap0532Secret) || strings.Contains(resp.AdditionalContext, gap0532Secret) {
		t.Fatal("the secret value is echoed back in the hook answer")
	}
}

// The AWS documentation pair (AKIAIOSFODNN7EXAMPLE and its example secret) is
// a public placeholder, not a credential: knownPublicCredentialExample drops
// it for both AWS rules, in prose and in a credentials file. This is the
// placeholder policy the J04 cells hit; it stays as it is.
func TestAWSDocumentedExamplePairStaysExemptGAP0532(t *testing.T) {
	api := gap0532ClaudeCodeAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "My AWS key is " + gap0532DocKeyID + " and the secret is " + gap0532DocSecret + ". Remember them.",
	})
	for _, rule := range []string{"SEC-AWS-KEY", "SEC-AWS-SECRET"} {
		if hasRuleFindingGAP0532(resp.Findings, rule) {
			t.Errorf("documented example prompt findings = %v, want no %s", resp.Findings, rule)
		}
	}
	for _, text := range []string{
		"[default]\naws_access_key_id = " + gap0532DocKeyID + "\naws_secret_access_key = " + gap0532DocSecret + "\n",
		`{"AccessKeyId": "` + gap0532DocKeyID + `", "SecretAccessKey": "` + gap0532DocSecret + `"}`,
		gap0532DocKeyID + "," + gap0532DocSecret,
	} {
		for _, rule := range []string{"SEC-AWS-KEY", "SEC-AWS-SECRET"} {
			if scanHasRuleGAP0532(text, rule) {
				t.Errorf("documented example %q raised %s", text, rule)
			}
		}
	}
}

// A tool result that holds a non-placeholder secret access key is a
// SEC-AWS-SECRET finding in every way AWS tools write one. At the base commit
// only the unquoted INI line fired; the JSON, quoted, spaced-name and CSV
// forms had no finding.
func TestClaudeCodeToolResultAWSSecretFormsGAP0532(t *testing.T) {
	api := gap0532ClaudeCodeAPI()
	for name, stdout := range map[string]string{
		"ini lines":         "aws_access_key_id = " + gap0532KeyID + "\naws_secret_access_key = " + gap0532Secret + "\n",
		"cli json":          "{\n  \"Credentials\": {\n    \"AccessKeyId\": \"" + gap0532SessionKeyID + "\",\n    \"SecretAccessKey\": \"" + gap0532Secret + "\"\n  }\n}\n",
		"quoted assignment": "aws_secret_access_key = \"" + gap0532Secret + "\"\n",
		"spaced key name":   "AWS Secret Access Key: " + gap0532Secret + "\n",
		"csv row":           "Access key ID,Secret access key\n" + gap0532KeyID + "," + gap0532Secret + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PostToolUse",
				ToolName:      "Bash",
				ToolInput:     map[string]interface{}{"command": "cat secret-notes.txt"},
				ToolResponse:  map[string]interface{}{"stdout": stdout},
				CWD:           "/Users/alice/work",
			})
			if !hasRuleFindingGAP0532(resp.Findings, "SEC-AWS-SECRET") {
				t.Fatalf("tool result findings = %v, want SEC-AWS-SECRET", resp.Findings)
			}
			if strings.Contains(resp.Reason, gap0532Secret) || strings.Contains(resp.AdditionalContext, gap0532Secret) {
				t.Fatal("the secret value is echoed back in the hook answer")
			}
		})
	}
}

// The rule reads the forms directly too, including the JSON-escaped text of
// a tool response that was marshalled before the scan.
func TestAWSSecretRuleFormsGAP0532(t *testing.T) {
	for name, text := range map[string]string{
		"prose pair":            "key " + gap0532KeyID + " secret " + gap0532Secret,
		"session pair":          gap0532SessionKeyID + " / " + gap0532Secret,
		"camel case json":       `"secretAccessKey": "` + gap0532Secret + `"`,
		"escaped json":          `{\"SecretAccessKey\": \"` + gap0532Secret + `\"}`,
		"env aws_secret_key":    "AWS_SECRET_KEY=" + gap0532Secret,
		"yaml single quoted":    "aws_secret_access_key: '" + gap0532Secret + "'",
		"existing unquoted ini": "aws_secret_access_key=" + gap0532Secret,
	} {
		if !scanHasRuleGAP0532(text, "SEC-AWS-SECRET") {
			t.Errorf("%s: no SEC-AWS-SECRET finding", name)
		}
	}
}

// A 40-character base64 run is a secret access key only next to a key name
// or after a key id on the same line. A random run alone, a git SHA-1 after a
// key id, and a run on the line under a key id are not SEC-AWS-SECRET (the
// key id alone stays SEC-AWS-KEY).
func TestAWSSecretRuleNeedsAnAnchorGAP0532(t *testing.T) {
	for name, text := range map[string]string{
		"random run alone":         "checksum " + gap0532Unanchored + " ok",
		"random run in prose":      "the build artifact digest is " + gap0532Unanchored + " for this release",
		"key id then a commit":     "deployed with key " + gap0532KeyID + " at commit " + gap0532CommitSHA1Hex,
		"key id then an upper hex": "key " + gap0532KeyID + " id " + strings.ToUpper(gap0532CommitSHA1Hex),
		"run on the next line":     "key " + gap0532KeyID + "\n" + gap0532Unanchored,
		"run longer than a secret": "key " + gap0532KeyID + " blob " + gap0532Unanchored + "Xk3",
		"secret name, a reference": "secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY_FROM_THE_ENVIRONMENT",
	} {
		if scanHasRuleGAP0532(text, "SEC-AWS-SECRET") {
			t.Errorf("%s: unexpected SEC-AWS-SECRET finding", name)
		}
	}
	if !scanHasRuleGAP0532("deployed with key "+gap0532KeyID+" at commit "+gap0532CommitSHA1Hex, "SEC-AWS-KEY") {
		t.Error("the key id alone is no longer SEC-AWS-KEY")
	}
}

// The candidate of a key-pair match is the 40 characters that end it, so the
// documented secret after any key id is still the documented example.
func TestAWSSecretCandidateGAP0532(t *testing.T) {
	for _, test := range []struct {
		match, want string
	}{
		{gap0532KeyID + " and the secret is " + gap0532Secret + ".", gap0532Secret},
		{gap0532KeyID + "," + gap0532Secret, gap0532Secret},
		{`SecretAccessKey\": \"` + gap0532Secret, gap0532Secret},
		{"aws_secret_access_key = " + gap0532Secret, gap0532Secret},
	} {
		if got := awsSecretCandidate(test.match); got != test.want {
			t.Errorf("awsSecretCandidate(%q) = %q, want %q", test.match, got, test.want)
		}
	}
	if acceptedCredentialMatch("SEC-AWS-SECRET", gap0532KeyID+" secret "+gap0532DocSecret+".") {
		t.Error("the documented secret after a key id was accepted")
	}
	if !acceptedCredentialMatch("SEC-AWS-SECRET", gap0532DocKeyID+" secret "+gap0532Secret+".") {
		t.Error("a random secret after the documented key id was dropped")
	}
}
