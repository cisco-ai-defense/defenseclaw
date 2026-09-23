// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type sshAuthorizedKeysConformanceCase struct {
	ID                   string   `json:"id"`
	Tool                 string   `json:"tool"`
	CommandTemplate      string   `json:"command_template"`
	ArgsTemplate         string   `json:"args_template"`
	CWD                  string   `json:"cwd"`
	ActiveHome           string   `json:"active_home"`
	Outcome              string   `json:"outcome"`
	PolicyPresent        bool     `json:"policy_present"`
	ApprovedFingerprints []string `json:"approved_fingerprints"`
	Want                 string   `json:"want"`
	WantReason           string   `json:"want_reason"`
}

func TestSSHAuthorizedKeysProtectionConformance(t *testing.T) {
	keyA, fingerprintA := deterministicSSHAuthorizedKey(t, 0x11)
	keyB, fingerprintB := deterministicSSHAuthorizedKey(t, 0x22)
	replacements := strings.NewReplacer(
		"{{KEY_A}}", keyA,
		"{{KEY_B}}", keyB,
		"{{FP_A}}", fingerprintA,
		"{{FP_B}}", fingerprintB,
	)

	stream, err := os.Open("testdata/ssh_authorized_keys_protection.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		var test sshAuthorizedKeysConformanceCase
		if err := json.Unmarshal(scanner.Bytes(), &test); err != nil {
			t.Fatalf("decode conformance fixture: %v", err)
		}
		t.Run(test.ID, func(t *testing.T) {
			command := replacements.Replace(test.CommandTemplate)
			args := json.RawMessage(replacements.Replace(test.ArgsTemplate))
			input := Input{
				Tool:       test.Tool,
				Command:    command,
				Args:       args,
				CWD:        test.CWD,
				ActiveHome: test.ActiveHome,
			}
			var policy *SSHAuthorizedKeysProtectionPolicy
			if test.PolicyPresent {
				approved := make([]string, len(test.ApprovedFingerprints))
				for index, value := range test.ApprovedFingerprints {
					approved[index] = replacements.Replace(value)
				}
				policy = &SSHAuthorizedKeysProtectionPolicy{
					ApprovedKeyFingerprints: approved,
				}
			}
			result := EvaluateSSHAuthorizedKeysProtection(
				input,
				Analyze(input),
				SSHAuthorizedKeysWriteOutcome(test.Outcome),
				policy,
			)
			if string(result.Decision) != test.Want {
				t.Fatalf(
					"decision=%q reason=%q fact=%+v, want %q",
					result.Decision,
					result.Reason,
					result.Fact,
					test.Want,
				)
			}
			if string(result.Reason) != test.WantReason {
				t.Fatalf(
					"reason=%q decision=%q fact=%+v, want %q",
					result.Reason,
					result.Decision,
					result.Fact,
					test.WantReason,
				)
			}
			if result.Decision == SSHAuthorizedKeysProtectionBlock &&
				result.Fact.Fingerprint == "" {
				t.Fatal("blocking result omitted the stable fingerprint")
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSSHAuthorizedKeyFingerprintIgnoresCommentAndWhitespace(t *testing.T) {
	key, fingerprint := deterministicSSHAuthorizedKey(t, 0x33)
	parsedA, reason := parseLiteralSSHAuthorizedKey(key + " fixture-a")
	if reason != "" {
		t.Fatalf("parse first key: %s", reason)
	}
	parsedB, reason := parseLiteralSSHAuthorizedKey("  " + key + " fixture-b\n")
	if reason != "" {
		t.Fatalf("parse second key: %s", reason)
	}
	if got := ssh.FingerprintSHA256(parsedA); got != fingerprint {
		t.Fatalf("first fingerprint=%q, want %q", got, fingerprint)
	}
	if got := ssh.FingerprintSHA256(parsedB); got != fingerprint {
		t.Fatalf("second fingerprint=%q, want %q", got, fingerprint)
	}
}

func TestSSHAuthorizedKeysProtectionRejectsOversizedAllowlist(t *testing.T) {
	key, _ := deterministicSSHAuthorizedKey(t, 0x44)
	input := Input{
		Tool:       "shell",
		Command:    "echo '" + key + "' >> /home/alice/.ssh/authorized_keys",
		CWD:        "/repo",
		ActiveHome: "/home/alice",
	}
	policy := &SSHAuthorizedKeysProtectionPolicy{
		ApprovedKeyFingerprints: make(
			[]string,
			maxSSHAuthorizedKeysApprovedFingerprints+1,
		),
	}
	result := EvaluateSSHAuthorizedKeysProtection(
		input,
		Analyze(input),
		SSHAuthorizedKeysWriteOutcomeSucceeded,
		policy,
	)
	if result.Decision != SSHAuthorizedKeysProtectionAbstain ||
		result.Reason != SSHAuthorizedKeysReasonInvalidPolicy {
		t.Fatalf("oversized allowlist result=%+v", result)
	}
}

func deterministicSSHAuthorizedKey(t *testing.T, fill byte) (string, string) {
	t.Helper()
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	return line, ssh.FingerprintSHA256(publicKey)
}
