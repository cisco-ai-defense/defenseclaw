// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFirstSubmatch_ParsesCodesignFixtures exercises the two regex
// extractors against real codesign(1) output shapes. Full-fat sample
// captured from `codesign -dv --verbose=4 /bin/zsh` and a synthetic
// Team-ID-signed record.
func TestFirstSubmatch_ParsesCodesignFixtures(t *testing.T) {
	cases := []struct {
		name        string
		stderr      string
		wantTeam    string
		wantSigning string
	}{
		{
			name: "apple system binary — Identifier only, TeamIdentifier=not set",
			stderr: `Executable=/bin/zsh
Identifier=com.apple.zsh
Format=pid diskrep
CodeDirectory v=20400 size=5382 flags=0x0(none) hashes=163+2 location=embedded
Platform identifier=26
TeamIdentifier=not set`,
			wantTeam:    "", // collapsed from "not set" → ""
			wantSigning: "com.apple.zsh",
		},
		{
			name: "third-party developer-ID signed app",
			stderr: `Executable=/Applications/Cisco/SecureClient.app/Contents/MacOS/SecureClient
Identifier=com.cisco.secureclient
Format=app bundle with Mach-O universal
TeamIdentifier=ABC12345XY`,
			wantTeam:    "ABC12345XY",
			wantSigning: "com.cisco.secureclient",
		},
		{
			name:        "no signature at all",
			stderr:      `Error: /tmp/unsigned: code object is not signed at all`,
			wantTeam:    "",
			wantSigning: "",
		},
		{
			name:        "empty stderr",
			stderr:      "",
			wantTeam:    "",
			wantSigning: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			team := firstSubmatch(teamIDRe, []byte(tc.stderr))
			signing := firstSubmatch(signingIDRe, []byte(tc.stderr))
			// Apply the same "not set" collapse the real reader does.
			if strings.EqualFold(strings.TrimSpace(team), "not") {
				team = ""
			}
			if team != tc.wantTeam {
				t.Errorf("teamID: got %q, want %q", team, tc.wantTeam)
			}
			if signing != tc.wantSigning {
				t.Errorf("signingID: got %q, want %q", signing, tc.wantSigning)
			}
		})
	}
}

// TestReadCodesignForPID_LivesShellsToCodesign smoke-runs the real
// darwin implementation against the test process itself. Skipped
// when /usr/bin/codesign is unavailable (should never happen on a
// real Mac, but keeps the test hermetic on stripped CI images).
func TestReadCodesignForPID_LivesShellsToCodesign(t *testing.T) {
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("codesign not on PATH")
	}
	// Read our own PID's codesign metadata. Signing ID will exist
	// (Go test binaries are ad-hoc signed on darwin); Team ID is
	// almost always "not set" for these, i.e. empty after collapse.
	pid := int32(1) // launchd is always signed, always PID 1 on darwin
	_, signing, err := readCodesignForPID(pid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// launchd is always signed with Identifier=com.apple.xpc.launchd.
	if signing == "" {
		t.Errorf("expected non-empty signing identifier for PID 1 (launchd)")
	}
}

// TestCodesignValidatingListener_AllowlistMatch exercises the
// accept-time allow() decision without opening a real socket. We
// use a small stub net.Listener + net.Conn to feed synthetic
// peerIdentity values through the wrapper. This is the layer that
// enforces the reviewer-agreed "TeamID OR SigningID" semantics.
func TestCodesignValidatingListener_AllowlistMatch(t *testing.T) {
	cases := []struct {
		name          string
		teamAllowlist []string
		signAllowlist []string
		id            peerIdentity
		wantAllow     bool
	}{
		{
			name:          "both allowlists empty → wrapper is not applied",
			teamAllowlist: nil,
			signAllowlist: nil,
			id:            peerIdentity{TeamID: "ANYTHING", SigningID: "any"},
			wantAllow:     true, // wrapper returns inner; every accept passes
		},
		{
			name:          "match via TeamID",
			teamAllowlist: []string{"ABC12345XY"},
			id:            peerIdentity{TeamID: "ABC12345XY", SigningID: "com.cisco.secureclient"},
			wantAllow:     true,
		},
		{
			name:          "match via SigningID (no team allowlist)",
			signAllowlist: []string{"com.cisco.secureclient"},
			id:            peerIdentity{TeamID: "", SigningID: "com.cisco.secureclient"},
			wantAllow:     true,
		},
		{
			name:          "unsigned peer + allowlist configured → reject",
			teamAllowlist: []string{"ABC12345XY"},
			id:            peerIdentity{TeamID: "", SigningID: ""},
			wantAllow:     false,
		},
		{
			name:          "signed but wrong Team + no signing match → reject",
			teamAllowlist: []string{"ABC12345XY"},
			signAllowlist: []string{"com.cisco.secureclient"},
			id:            peerIdentity{TeamID: "ZZZZZZZZZZ", SigningID: "com.rando.app"},
			wantAllow:     false,
		},
		{
			name:          "empty-string entries are ignored",
			teamAllowlist: []string{"", ""},
			signAllowlist: []string{"", ""},
			id:            peerIdentity{TeamID: "anything", SigningID: "anything"},
			wantAllow:     true, // wrapper degrades to no-op when everything is empty
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &nopListener{}
			var logged bool
			logFn := func(peerIdentity, string) { logged = true }
			wrapped := newCodesignValidatingListener(inner, tc.teamAllowlist, tc.signAllowlist, logFn)

			// If the wrapper returned inner verbatim (empty
			// allowlist branch), the allow decision is "always
			// allow" — we assert that by identity, since
			// codesignValidatingListener.allow is unreachable.
			if wrapped == inner {
				if !tc.wantAllow {
					t.Fatalf("wrapper degraded to no-op but test expected reject")
				}
				return
			}

			// Real wrapper — assert allow() directly. Peeking
			// past the interface into the concrete type is fine
			// in a same-package test.
			l := wrapped.(*codesignValidatingListener)
			got := l.allow(tc.id)
			if got != tc.wantAllow {
				t.Errorf("allow(%+v) = %v, want %v", tc.id, got, tc.wantAllow)
			}
			if !tc.wantAllow && logged {
				// allow() does not log; reject() does. Passing
				// the id through allow() alone should not touch
				// the log callback.
				t.Errorf("logRejectFn fired during allow() — unexpected")
			}
		})
	}
}

// nopListener satisfies net.Listener without opening a real socket.
// Only used to satisfy the wrapper's constructor signature; Accept
// is never called by these tests.
type nopListener struct{}

func (nopListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (nopListener) Close() error              { return nil }
func (nopListener) Addr() net.Addr            { return dummyAddr(0) }

type dummyAddr int

func (dummyAddr) Network() string { return "unix" }
func (dummyAddr) String() string  { return filepath.Join("", "dummy.sock") }
