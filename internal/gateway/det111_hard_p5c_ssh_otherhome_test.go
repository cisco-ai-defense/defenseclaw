// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP2135OtherHomeSSHKeyReadA64Cells pins the two a64 other-account
// private-key reads and another key spelling to the approved HIGH alert
// floor outside strict and CRITICAL block in strict, on both hook routes.
func TestGAP2135OtherHomeSSHKeyReadA64Cells(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX account-home spellings")
	}
	t.Setenv("HOME", "/home/active")
	for _, row := range []struct{ name, command string }{
		{"other-home", "cat ~bob/.ssh/id_rsa"},
		{"root-home", "cat /root/.ssh/id_rsa"},
		{"root-ed25519", "cat /root/.ssh/id_ed25519"},
	} {
		for _, tier := range boundedTestTiers {
			for _, route := range r3PosixRoutesForReadRows() {
				t.Run(row.name+"/"+tier.name+"/"+route.connector, func(t *testing.T) {
					api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
					action, severity := route.decide(t, api, "/home/active/proj", row.command)
					wantAction, wantSeverity := "alert", "HIGH"
					if tier.posture == "strict" {
						wantAction, wantSeverity = "block", "CRITICAL"
					}
					if action != wantAction || severity != wantSeverity {
						t.Errorf("action/severity=%s/%s, want %s/%s", action, severity, wantAction, wantSeverity)
					}
				})
			}
		}
	}
}

// TestGAP2135OtherHomePathProof keeps the other-account distinction on the
// same action facts used by the context disposition reader.
func TestGAP2135OtherHomePathProof(t *testing.T) {
	for _, command := range []string{"cat ~bob/.ssh/id_rsa", "cat /root/.ssh/id_rsa", "cat /root/.ssh/id_ed25519"} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: command, CWD: "/home/active/proj", ActiveHome: "/home/active", DialectHint: actionfacts.DialectPOSIX})
		if !trustedActionOtherHomeSSHPrivateKeyContentRead(facts.EnforcementProjection()) {
			t.Error("other-home private-key content read was not proven")
		}
		if trustedActionActiveSSHPrivateKeyContentRead(facts.EnforcementProjection()) {
			t.Error("other-home private-key content read was mistaken for the active home")
		}
	}
}

func TestGAP2135OtherHomeReadProofExcludesOwnKeyAndIdentityUse(t *testing.T) {
	for _, tc := range []struct{ name, command string }{
		{"active key", "cat /home/active/.ssh/id_rsa"},
		{"active private copy", "cp /home/active/.ssh/id_rsa /home/active/.ssh/id_rsa.bak"},
		{"other key identity consumer", "ssh -i /root/.ssh/id_rsa host.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: "/home/active/proj", ActiveHome: "/home/active", DialectHint: actionfacts.DialectPOSIX})
			if trustedActionOtherHomeSSHPrivateKeyContentRead(facts.EnforcementProjection()) {
				t.Fatal("non-content or own-key operation promoted as another-account private-key read")
			}
		})
	}
}

// TestGAP2135DotTildePrefixesAreNotOtherHomes keeps literal ~. and ~..
// directory names outside the other-account credential-read proof. Quoting the
// same prefixes must keep the same allow verdict on both hook routes.
func TestGAP2135DotTildePrefixesAreNotOtherHomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX tilde spellings")
	}
	t.Setenv("HOME", "/home/active")
	useEffectsRulesMode(t, "on")
	for _, row := range []struct{ name, command string }{
		{"dot", "cat ~./root/.ssh/id_rsa"},
		{"dotdot", "cat ~../root/.ssh/id_rsa"},
		{"quoted-dot", "cat '~.'/root/.ssh/id_rsa"},
		{"quoted-dotdot", "cat '~..'/root/.ssh/id_rsa"},
	} {
		for _, tier := range boundedTestTiers {
			for _, route := range r3PosixRoutesForReadRows() {
				t.Run(row.name+"/"+tier.name+"/"+route.connector, func(t *testing.T) {
					api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
					action, severity := route.decide(t, api, "/home/active/proj", row.command)
					if action != "allow" || severity != "NONE" {
						t.Errorf("action/severity=%s/%s, want allow/NONE", action, severity)
					}
				})
			}
		}
	}
}
