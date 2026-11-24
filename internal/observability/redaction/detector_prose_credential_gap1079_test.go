// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-1079: a value introduced as a password, passphrase or secret in prose
// ("my password is X") is a credential whatever its length. Before, only the
// 20-character high-entropy floor caught it, so an 18-character prose password
// stayed in clear in the llm_prompt audit rows. Generated canaries only.

var gap1079Canaries = []string{
	"Sv5-Pw-canary-Zq81", // 18 characters, the J22 shape
	"Xk9#mLp2vQ",
	"Hunt3r!Pass",
	"correct-Horse-4-battery",
	"P@ssw0rd2026",
	"tr0ub4dor&3",
	"Zq81_aB3x-Kp7",
}

func gap1079Redact(t *testing.T, input string, class observability.FieldClass) string {
	t.Helper()
	profile, ok := BuiltInProfile(ProfileSensitive)
	if !ok {
		t.Fatal("no sensitive profile")
	}
	result, err := DetectAndRedact(input, class, profile.DetectorGroups(), bytes.Repeat([]byte{0x42}, 32), nil)
	if err != nil {
		t.Fatalf("%q: %v", input, err)
	}
	return result.Value
}

func TestProsePasswordIsRedactedGAP1079(t *testing.T) {
	t.Parallel()
	forms := []string{
		"my password is %s",
		"my password is %s.",
		"My Password Is %s, thanks",
		"the password is: %s",
		"the passphrase was %s and it was rotated",
		"summarise this text: my password is %s (do not share)",
		"my password is '%s'",
		"my password is \"%s\".",
		"my password is `%s`",
		"the secret is %s;",
		"I set the password to %s yesterday",
		"first line\nthe admin password will be %s\nlast line",
		"the new password should be %s!",
		"password: %s in the ticket",
		"his passphrase is %s",
	}
	for _, value := range gap1079Canaries {
		for _, form := range forms {
			input := fmt.Sprintf(form, value)
			for _, class := range []observability.FieldClass{observability.FieldClassContent, observability.FieldClassEvidence} {
				out := gap1079Redact(t, input, class)
				if strings.Contains(out, value) {
					t.Errorf("%s: the prose password stays in %q", class, out)
				}
				if !strings.Contains(out, "<redacted type=") {
					t.Errorf("%s: no replacement marker in %q", class, out)
				}
			}
		}
	}
}

func TestProsePasswordRecognizerIsExactGAP1079(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ input, value string }{
		{"my password is Sv5-Pw-canary-Zq81", "Sv5-Pw-canary-Zq81"},
		{"my password is Sv5-Pw-canary-Zq81.", "Sv5-Pw-canary-Zq81"},
		{"the passphrase was 'Xk9#mLp2vQ', ok", "Xk9#mLp2vQ"},
		{"set the password to P@ssw0rd2026 now", "P@ssw0rd2026"},
	} {
		assertDetectorExact(t, "secrets.assignment", c.input, c.value)
	}
}

// Prose that only mentions a password stays readable: a word, a short or
// single-class value, a placeholder, a path, a URL, a name with hyphens.
func TestProsePasswordControlsStayPlainGAP1079(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"the password is wrong",
		"password is required",
		"my password is in the vault",
		"reset your password is the next step",
		"password is: ********",
		"your password is Required",
		"the password is too short",
		"the password is Case-Sensitive",
		"the password is Two-Factor-Auth",
		"the password is multi-factor",
		"the password is 12345678",
		"the password is abcdefghijkl",
		"the password is ${DB_PASSWORD}",
		"the password is <your-password>",
		"the password is $DB_PASSWORD",
		"the password is /etc/passwd2",
		"the password is https://vault.example.test/Path1",
		"the password is os.Getenv(\"X1\")",
		"the password is config.Password1",
		"the password is Sv5-Pw1",
		"the passphrase was rotated on Monday, the secret is stored in Vault",
		"Enter the password you set at install time. The secret is never logged.",
		"A password is a secret. A secret is a value that is not shown.",
		"if the password is wrong the login fails; the secret is rotated daily",
		"password to the vault",
		"the old password was Temp2",
	} {
		for _, class := range []observability.FieldClass{observability.FieldClassContent, observability.FieldClassEvidence} {
			if out := gap1079Redact(t, input, class); out != input {
				t.Errorf("%s: benign prose changed: %q -> %q", class, input, out)
			}
		}
	}
}

// 5,000 generated benign sentences that mention passwords, passphrases and
// secrets without giving one. None may change.
func TestProsePasswordBenignCorpusGAP1079(t *testing.T) {
	t.Parallel()
	leads := []string{"", "Note that ", "Please remember: ", "The admin said ", "If ", "Check whether ", "Support asked why ", "In the runbook, "}
	subjects := []string{"your password", "the password", "my passphrase", "the admin secret", "this secret", "the user's password", "a password", "the passphrase"}
	links := []string{"is", "was", "will be", "should be", "to", "is:"}
	tails := []string{
		"wrong", "required", "in the vault", "the next step", "stored in the keychain", "too short", "expired",
		"managed by IT", "not shared", "********", "hidden", "case-sensitive", "rotated every 90 days",
		"Two-Factor-Auth", "multi-factor", "up to date", "Okta-managed", "Single-Sign-On", "reset by the Helpdesk",
		"valid for 24 hours", "never logged", "set by the installer", "different from the username", "too common",
		"sent by email", "a secret", "the same as before", "asked for twice", "checked against the policy", "empty",
		"Not-Required", "Read-Only", "End-to-End", "Out-of-Band", "Self-Service",
	}
	var corpus []string
	for _, tail := range tails {
		for _, link := range links {
			for _, subject := range subjects {
				for _, lead := range leads {
					corpus = append(corpus, lead+subject+" "+link+" "+tail+".")
				}
			}
		}
	}
	if len(corpus) < 5000 {
		t.Fatalf("corpus has %d sentences", len(corpus))
	}
	changed := 0
	for _, sentence := range corpus[:5000] {
		if out := gap1079Redact(t, sentence, observability.FieldClassContent); out != sentence {
			changed++
			if changed <= 5 {
				t.Errorf("benign sentence changed: %q -> %q", sentence, out)
			}
		}
	}
	t.Logf("benign sentences: 5000, changed: %d", changed)
	if changed != 0 {
		t.Fatalf("%d of 5000 benign sentences changed", changed)
	}
}

// Every profile that redacts secrets takes the prose password, so each sink
// (the laptop and cluster audit stores, OTLP, Galileo, the local destination)
// that projects through DetectAndRedact with one of them is covered.
func TestProsePasswordInEveryRedactingProfileGAP1079(t *testing.T) {
	t.Parallel()
	for _, name := range []ProfileName{ProfileSensitive, ProfileContent, ProfileStrict} {
		profile, ok := BuiltInProfile(name)
		if !ok {
			t.Fatalf("no %s profile", name)
		}
		input := "summarise: my password is " + gap1079Canaries[0] + " and keep it"
		result, err := DetectAndRedact(input, observability.FieldClassContent, profile.DetectorGroups(), bytes.Repeat([]byte{0x42}, 32), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(result.Value, gap1079Canaries[0]) {
			t.Errorf("%s: the prose password stays in %q", name, result.Value)
		}
	}
}
