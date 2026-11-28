// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// accepted is the text of the credential-context candidates the recognizers
// accept in input.
func gap0654Accepted(input string) []string {
	var out []string
	for _, found := range [][]candidate{recognizeInlineCredentials(input), recognizeCredentialKeys(input)} {
		for _, item := range found {
			if item.accepted {
				out = append(out, input[item.start:item.end])
			}
		}
	}
	return out
}

// GAP-0654: the all-digit count exemption is for count keys (a bare token,
// prompt_token, last_token), not for a credential key that ends in token.
// GAP-0655: a bare token key keeps a word or a count, not a short value of
// digits and symbols, 11 or more digits, or symbols only.
// GAP-0656: a quoted value whose closing quote is past the 8 KiB bound is
// redacted from its first word, as the parent did, never kept whole.
func TestGAP0654GAP0655GAP0656CredentialValuesAreRedacted(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("Q7", 4200)
	for _, tc := range []struct{ input, want string }{
		{"SERVICE_API_TOKEN=12345678", "12345678"},
		{"export SERVICE_API_TOKEN=1234567890", "1234567890"},
		{`{"deploy_token": "87654321"}`, "87654321"},
		{"SERVICE_TOKEN: 4815162342", "4815162342"},
		{`{"token": "12345678901"}`, "12345678901"},
		{`{"token": "1234-5678-90"}`, "1234-5678-90"},
		{`{"token": "!@#$%^&*"}`, "!@#$%^&*"},
		{"CANARY_TOKEN='" + long + " tail'", long},
		{"db_password: '" + long + "'", long},
	} {
		got := gap0654Accepted(tc.input)
		if len(got) != 1 || got[0] != tc.want {
			short := tc.input
			if len(short) > 60 {
				short = short[:60] + "..."
			}
			t.Errorf("%q: accepted %d spans, want the value redacted", short, len(got))
		}
	}
	// The counts, words and tokenizer output the exemptions are for keep
	// every byte.
	for _, input := range []string{
		"prompt_token: 12345678",
		"last_token: 4096",
		`{"token": 12345}`,
		`{"token": "1234567890"}`,
		`{"token": "Hello!"}`,
		`{"token": "...."}`,
		`{"token": "----"}`,
		`{"max_token": 8192, "total_token": 1048576}`,
	} {
		if got := gap0654Accepted(input); len(got) != 0 {
			t.Errorf("%q: new credential-context match %q", input, got)
		}
	}
}
