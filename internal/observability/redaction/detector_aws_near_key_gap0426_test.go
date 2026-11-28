// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-0426 round 4: an AWS-prefixed near-key (a key id with one to sixteen
// extra key characters, as the J22 canaries AKIA+17 and AKIA+18 are) is
// redacted like a real 20-character key id, in a .env line, in prose and
// after '='. Generated shapes, never the live canaries.
func TestAWSNearKeyIsRedactedGAP0426(t *testing.T) {
	t.Parallel()
	near := []string{
		"AKIA" + "Q7T6NEARKEY000201",                // 21
		"AKIA" + "Q7T6NEARKEYPROBE01",               // 22
		"ASIA" + "Q7T6NEARKEYPROBE0102",             // 24
		"AROA" + "Q7T6NEARKEYPROBE0102030405060708", // 36: the longest near-key
	}
	real := []string{
		"AKIA" + "Z3Q7XK9M2P4W8R5T",
		"AKIA" + "QZXWVUTSRPONMLKJ", // no digit: a real key id needs none
		"ANVA" + "2345672345672345",
	}
	for _, token := range append(append([]string(nil), near...), real...) {
		for _, input := range []string{
			token,
			"Create .env containing CANARY_KEY=" + token + " and more",
			"Summarise this text: my key is " + token + ".",
			"created\nAWS_ACCESS_KEY_ID=" + token + "\n",
			`{"key":"` + token + `"}`,
			"the key id " + token + "-rotated, then " + token + "+1",
		} {
			assertDetectorExact(t, "credentials.api_token", input, token)
		}
	}
	// Benign controls: an uppercase word or heading that starts like a key
	// id but has no digit, a run past the near-key length, a lowercase or
	// left-joined copy, a short id, and a key joined to more token text.
	for _, input := range []string{
		"ASIA" + "PACIFICHEADQUARTERS",
		"AIDA" + "NANDTHEREVIEWBOARD",
		"AKIA" + "Q7T6NEARKEYPROBE01020304050607080", // AKIA + 33
		strings.ToLower("AKIA" + "Q7T6NEARKEYPROBE01"),
		"X" + "AKIA" + "Q7T6NEARKEYPROBE01",
		"AKIA" + "Q7T6NEARKEY0002", // 19
		"AKIA" + "Q7T6NEARKEYPROBE01" + "_tail",
		"AKIA" + "Z3Q7XK9M2P4W8R5T" + "x",
		"AKIA",
	} {
		assertDetectorAbsent(t, "credentials.api_token", input)
	}
	// The whole sensitive profile still leaves ordinary text alone.
	profile, _ := BuiltInProfile(ProfileSensitive)
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, input := range []string{
		"The ASIA" + "PACIFICHEADQUARTERS team meets on Friday.",
		"AKIA is the prefix of an AWS access key id.",
	} {
		result, err := DetectAndRedact(input, observability.FieldClassContent, profile.DetectorGroups(), key, nil)
		if err != nil || result.Value != input {
			t.Errorf("benign text changed: %q -> %q (%v)", input, result.Value, err)
		}
	}
}
