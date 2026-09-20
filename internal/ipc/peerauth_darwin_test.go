// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFirstSubmatch_ParsesCodesignFixtures exercises the three
// regex extractors against real codesign(1) output shapes.
func TestFirstSubmatch_ParsesCodesignFixtures(t *testing.T) {
	cases := []struct {
		name        string
		stderr      string
		wantExe     string
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
			wantExe:     "/bin/zsh",
			wantTeam:    "", // collapsed from "not set" → ""
			wantSigning: "com.apple.zsh",
		},
		{
			name: "third-party developer-ID signed app (bundle path)",
			stderr: `Executable=/Applications/Cisco/Cisco Secure Client.app/Contents/MacOS/SecureClient
Identifier=com.cisco.secureclient.gui
Format=app bundle with Mach-O universal
TeamIdentifier=DE8Y96K9QP`,
			wantExe:     "/Applications/Cisco/Cisco Secure Client.app/Contents/MacOS/SecureClient",
			wantTeam:    "DE8Y96K9QP",
			wantSigning: "com.cisco.secureclient.gui",
		},
		{
			name:        "no signature at all",
			stderr:      `Error: /tmp/unsigned: code object is not signed at all`,
			wantExe:     "",
			wantTeam:    "",
			wantSigning: "",
		},
		{
			name:        "empty stderr",
			stderr:      "",
			wantExe:     "",
			wantTeam:    "",
			wantSigning: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exe := firstSubmatch(executableRe, []byte(tc.stderr))
			team := firstSubmatch(teamIDRe, []byte(tc.stderr))
			signing := firstSubmatch(signingIDRe, []byte(tc.stderr))
			// Apply the same "not set" collapse the real reader does.
			if strings.EqualFold(strings.TrimSpace(team), "not") {
				team = ""
			}
			if exe != tc.wantExe {
				t.Errorf("exe: got %q, want %q", exe, tc.wantExe)
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

// TestBundleIDFromExecutable_WalksToApp verifies the ".app
// ancestor" walk against a synthetic path tree with plutil stubbed
// out. plutil is invoked only after the walk finds a `.app` dir,
// so a non-bundle exe path exits before plutilBinary is ever run.
func TestBundleIDFromExecutable_WalksToApp(t *testing.T) {
	// Test-scope stub: instead of the real plutil, run a shell
	// that echoes a canned bundle id back on stdout so we can
	// verify the resolver plumbs args correctly without depending
	// on a real Info.plist on disk.
	tmp := t.TempDir()
	stubBundleID := "com.cisco.secureclient.gui"
	stub := filepath.Join(tmp, "fake_plutil.sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho "+stubBundleID+"\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	orig := plutilBinary
	origTimeout := plutilTimeout
	plutilBinary = stub
	plutilTimeout = 15 * time.Second
	t.Cleanup(func() {
		plutilBinary = orig
		plutilTimeout = origTimeout
	})

	cases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "walks up to Cisco Secure Client.app",
			path: "/Applications/Cisco/Cisco Secure Client.app/Contents/MacOS/SecureClient",
			want: stubBundleID,
		},
		{
			name: "walks up multiple levels",
			path: "/Applications/Foo.app/Contents/Frameworks/Bar.framework/Versions/A/Bar",
			// First .app ancestor is Foo.app.
			want: stubBundleID,
		},
		{
			name: "non-bundle CLI exe → empty",
			path: "/usr/bin/grpcurl",
			want: "",
		},
		{
			name: "empty path → empty",
			path: "",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bundleIDFromExecutable(tc.path); got != tc.want {
				t.Errorf("bundleIDFromExecutable(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestReadCodesignForPID_LivesShellsToCodesign smoke-runs the real
// darwin implementation against launchd (PID 1), which is always
// signed with Identifier=com.apple.xpc.launchd. Skipped when
// /usr/bin/codesign is unavailable (should never happen on a real
// Mac, but keeps the test hermetic on stripped CI images).
func TestReadCodesignForPID_LivesShellsToCodesign(t *testing.T) {
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("codesign not on PATH")
	}
	_, signing, _, exePath, err := readCodesignForPID(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signing == "" {
		t.Errorf("expected non-empty signing identifier for PID 1 (launchd)")
	}
	if exePath == "" {
		t.Errorf("expected non-empty exe path for PID 1")
	}
}

// TestCodesignValidatingListener_ANDSemantics exercises the
// accept-time allow() decision under the new AND-with-precondition
// policy: peer must clear every configured check.
func TestCodesignValidatingListener_ANDSemantics(t *testing.T) {
	// Cisco Secure Client GUI reference identity.
	const (
		team    = "DE8Y96K9QP"
		signing = "com.cisco.secureclient.gui"
		bundle  = "com.cisco.secureclient.gui"
	)
	unixPeer := peerIdentity{
		Kind: KindUnixPeer, TeamID: team, SigningID: signing, BundleID: bundle,
	}

	cases := []struct {
		name         string
		team         []string
		sign         []string
		bundleIDs    []string
		reqUnix      bool
		reqSigningMd bool
		id           peerIdentity
		wantAccept   bool
		wantReason   string // substring; ignored when wantAccept
	}{
		{
			name:         "all three fields present + all match → accept",
			team:         []string{team},
			sign:         []string{signing},
			bundleIDs:    []string{bundle},
			reqUnix:      true,
			reqSigningMd: true,
			id:           unixPeer,
			wantAccept:   true,
		},
		{
			name:         "missing bundle id → incomplete",
			team:         []string{team},
			sign:         []string{signing},
			bundleIDs:    []string{bundle},
			reqUnix:      true,
			reqSigningMd: true,
			id:           peerIdentity{Kind: KindUnixPeer, TeamID: team, SigningID: signing},
			wantAccept:   false,
			wantReason:   "peer signing metadata incomplete",
		},
		{
			name:         "wrong bundle id → bundle id ... not allowed",
			team:         []string{team},
			sign:         []string{signing},
			bundleIDs:    []string{bundle},
			reqUnix:      true,
			reqSigningMd: true,
			id: peerIdentity{
				Kind: KindUnixPeer, TeamID: team, SigningID: signing, BundleID: "com.rando.app",
			},
			wantAccept: false,
			wantReason: "bundle id",
		},
		{
			name:         "wrong team + correct bundle → team id ... not allowed",
			team:         []string{team},
			sign:         []string{signing},
			bundleIDs:    []string{bundle},
			reqUnix:      true,
			reqSigningMd: true,
			id: peerIdentity{
				Kind: KindUnixPeer, TeamID: "ZZZZZZZZZZ", SigningID: signing, BundleID: bundle,
			},
			wantAccept: false,
			wantReason: "team id",
		},
		{
			name:         "empty Kind + requireUnixPeer → peer kind must be UnixPeer",
			team:         []string{team},
			sign:         []string{signing},
			bundleIDs:    []string{bundle},
			reqUnix:      true,
			reqSigningMd: true,
			id: peerIdentity{
				TeamID: team, SigningID: signing, BundleID: bundle,
			},
			wantAccept: false,
			wantReason: "peer kind must be UnixPeer",
		},
		{
			name:       "nothing configured → wrapper bypassed (inner returned)",
			id:         unixPeer,
			wantAccept: true,
		},
		{
			name:       "empty-string entries alone still bypass wrapper",
			team:       []string{"", ""},
			sign:       []string{""},
			bundleIDs:  []string{""},
			id:         unixPeer,
			wantAccept: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &nopListener{}
			wrapped := newCodesignValidatingListener(inner,
				tc.team, tc.sign, tc.bundleIDs,
				tc.reqUnix, tc.reqSigningMd,
				func(peerIdentity, string) {})

			if wrapped == inner {
				// Bypassed → every accept passes.
				if !tc.wantAccept {
					t.Fatalf("wrapper bypassed but test expected reject")
				}
				return
			}
			l := wrapped.(*codesignValidatingListener)
			reason := l.allow(tc.id)
			gotAccept := reason == ""
			if gotAccept != tc.wantAccept {
				t.Errorf("allow: gotAccept=%v reason=%q, wantAccept=%v", gotAccept, reason, tc.wantAccept)
			}
			if !tc.wantAccept && !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason %q does not contain %q", reason, tc.wantReason)
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
