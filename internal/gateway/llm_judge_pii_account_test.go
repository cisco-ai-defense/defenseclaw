// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func piiJudgeReturning(t *testing.T, response string) *LLMJudge {
	t.Helper()
	finishReason := "stop"
	return &LLMJudge{
		cfg:   &config.JudgeConfig{Enabled: true, PII: true},
		model: "openai/gpt-judge", providerName: "openai",
		provider: &mockLLMProvider{response: &ChatResponse{
			ID: "judge-response-pii-account", Model: "openai/gpt-judge",
			Choices: []ChatChoice{{
				Message: &ChatMessage{Role: "assistant", Content: response}, FinishReason: &finishReason,
			}},
		}},
		rp: &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{}},
	}
}

const piiUsernameDevuser1 = `{"Email Address":{"detection_result":false,"entities":[]},` +
	`"IP Address":{"detection_result":false,"entities":[]},"Phone Number":{"detection_result":false,"entities":[]},` +
	`"Driver_s_License_Number":{"detection_result":false,"entities":[]},"Passport Number":{"detection_result":false,"entities":[]},` +
	`"Social Security Number":{"detection_result":false,"entities":[]},` +
	`"Username":{"detection_result":true,"entities":["devuser1"]},"Password":{"detection_result":false,"entities":[]}}`

// A benign coding-agent turn: the tool output of ls -la and pwd names the
// OS account only in owner/group columns and home paths. The PII judge
// reported it as a username, so every listing raised a LOW
// JUDGE-PII-USER alert (rel-1-0-6 GAP-0111).
func TestPIIJudgeIgnoresAccountNameInListingsAndPaths(t *testing.T) {
	for name, content := range map[string]string{
		"ls -la": "total 16\n" +
			"drwxr-xr-x. 5 devuser1 devuser1   90 Oct 31 13:59 .\n" +
			"drwx------. 9 devuser1 devuser1  191 Oct 31 14:00 ..\n" +
			"-rw-r--r--. 1 devuser1 devuser1    6 Oct 31 13:57 README.md\n" +
			"drwxr-xr-x. 2 devuser1 devuser1   19 Oct 31 13:57 src\n",
		"claude code bash tool_response JSON": `{"interrupted":false,"isImage":false,"stderr":"",` +
			`"stdout":"total 16\ndrwxr-xr-x. 5 devuser1 devuser1 90 Oct 31 13:59 .\n` +
			`drwx------. 9 devuser1 devuser1 191 Oct 31 14:00 ..\n-rw-r--r--. 1 devuser1 devuser1 6 Oct 31 13:57 README.md"}`,
		"pwd and paths": "/home/devuser1/proj\nwrote /home/devuser1/proj/src/a.txt (2 lines)\n",
		"windows path":  "Directory: C:\\Users\\devuser1\\proj\n    README.md",
		// The assistant re-quotes the tool's ls -l line in markdown (TST-4640).
		"markdown bullet code span": "- `drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 18:08 /home/devuser1/project`\n" +
			"- `/home/devuser1/bench`: No such file or directory",
		"markdown bullet plain":  "* drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 18:08 project\n1. -rw-r--r--. 1 devuser1 devuser1 6 Oct 31 a.txt",
		"markdown quote":         "> drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 18:08 project",
		"markdown table row":     "| drwxr-xr-x. | 4 | devuser1 | devuser1 | 48 | project |",
		"inline quote":           "The listing shows 'drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 18:08 project'.",
		"bold home path":         "Your project is in **/home/devuser1/project**.",
		"assistant JSON escaped": `{"message":"- ` + "`" + `drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 18:08 /home/devuser1/project` + "`" + `\n- done"}`,
		"macOS path quote":       "open \"/Users/devuser1/proj/README.md\": permission denied",
	} {
		t.Run(name, func(t *testing.T) {
			verdict := piiJudgeReturning(t, piiUsernameDevuser1).runPIIJudge(t.Context(), content, "completion", "Bash")
			if verdict.Action != "allow" || slices.Contains(verdict.Findings, "JUDGE-PII-USER") {
				t.Fatalf("benign account metadata raised %s %s %v", verdict.Action, verdict.Severity, verdict.Findings)
			}
		})
	}
}

// Controls: a username shared as data, also when the same name appears in a
// path elsewhere, still raises JUDGE-PII-USER, and other categories are not
// touched.
func TestPIIJudgeKeepsUsernameSharedAsData(t *testing.T) {
	for name, content := range map[string]string{
		"record":                    "customer record: name Jo Example, login devuser1, plan gold, renewal pending",
		"path and prose":            "/home/devuser1/proj/notes.txt says the account owner devuser1 asked for a reset",
		"listing and prose":         "-rw-r--r--. 1 devuser1 devuser1 6 Oct 31 13:57 a.txt\nticket from devuser1 about the invoice",
		"longer token":              "/home/devuser1x/proj and the user devuser1 called support",
		"URL path":                  "cloned https://git.example.com/devuser1/project.git into ./project",
		"non-home path":             "uploaded the export to /srv/exports/devuser1/",
		"bullet listing and prose":  "- `drwxr-xr-x. 4 devuser1 devuser1 48 Oct 31 project`\n- the owner devuser1 asked for a refund",
		"table with a login column": "| ticket | login |\n| 4411 | devuser1 |",
	} {
		t.Run(name, func(t *testing.T) {
			verdict := piiJudgeReturning(t, piiUsernameDevuser1).runPIIJudge(t.Context(), content, "completion", "Bash")
			if verdict.Action != "alert" || !slices.Contains(verdict.Findings, "JUDGE-PII-USER") {
				t.Fatalf("username shared as data: %s %s %v, want alert JUDGE-PII-USER", verdict.Action, verdict.Severity, verdict.Findings)
			}
		})
	}
	ssn := `{"Social Security Number":{"detection_result":true,"entities":["078-05-1120"]},` +
		`"Username":{"detection_result":true,"entities":["devuser1"]}}`
	content := "-rw-r--r--. 1 devuser1 devuser1 6 Oct 31 13:57 a.txt\nemployee ssn 078-05-1120\n"
	verdict := piiJudgeReturning(t, ssn).runPIIJudge(t.Context(), content, "completion", "Bash")
	if !slices.Contains(verdict.Findings, "JUDGE-PII-SSN") || slices.Contains(verdict.Findings, "JUDGE-PII-USER") ||
		verdict.Action != "block" {
		t.Fatalf("SSN control: %s %s %v, want block JUDGE-PII-SSN only", verdict.Action, verdict.Severity, verdict.Findings)
	}
}
