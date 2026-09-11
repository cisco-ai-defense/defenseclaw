// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestKindForIDOnlyLabelsWhatItCanPlace is the guard on the v8
// defenseclaw.user.id_kind enum. A hook payload is agent-controlled and can
// carry any string in the user field; labelling one of those posix_uid would
// put a value into the enum that consumers then join on as though it were a
// real uid.
func TestKindForIDOnlyLabelsWhatItCanPlace(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want string
	}{
		{"S-1-5-21-3623811015-3361044348-30300820-1013", KindWindowsSID},
		{"S-1-5-18", KindWindowsSID},
		{"501", KindPOSIXUID},
		{"0", KindPOSIXUID},
		{" 501 ", KindPOSIXUID},

		// Not identifiers, and each is something a payload could plausibly
		// carry in the same field.
		{"", ""},
		{"alice", ""},
		{"alice@example.com", ""},
		{"DOMAIN\\alice", ""},
		{"-1", ""},
		{"1.5", ""},
		{"S-1-5", ""},
		{"S-1-5-", ""},
		{"S-1-5-21-abc", ""},
		{"BA", ""},  // an SDDL alias, not an identifier
		{"007", ""}, // zero-padded: would join as a second "7"
		{strings.Repeat("1", maxIDLength+1), ""},
	} {
		if got := KindForID(tc.id); got != tc.want {
			t.Errorf("KindForID(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// TestHomeForIDRefusesUnclassifiableIDs keeps an unrecognized identifier from
// reaching the platform lookup at all. On POSIX that lookup is a passwd query,
// and passing it a login name would resolve a home directory for an id the
// caller could not vouch for.
func TestHomeForIDRefusesUnclassifiableIDs(t *testing.T) {
	for _, id := range []string{"", "   ", "alice", "alice@example.com", "-1", strings.Repeat("1", maxIDLength+1)} {
		if home := HomeForID(id); home != "" {
			t.Errorf("HomeForID(%q) = %q, want empty", id, home)
		}
	}
}

func TestCurrentReportsAClassifiableIdentity(t *testing.T) {
	got := Current()
	if got.Empty() {
		t.Fatalf("Current() resolved nothing on this host")
	}
	if runtime.GOOS != "windows" {
		if want := strconv.Itoa(os.Geteuid()); got.ID != want {
			t.Errorf("Current().ID = %q, want the effective uid %q", got.ID, want)
		}
		if got.IDKind != KindPOSIXUID {
			t.Errorf("Current().IDKind = %q, want %q", got.IDKind, KindPOSIXUID)
		}
	}
	if KindForID(got.ID) != got.IDKind {
		t.Errorf("Current() reported ID %q as %q, which does not classify that way", got.ID, got.IDKind)
	}
	// Current() reads the OS, never a credential file, so it must not invent
	// an address.
	if got.Email != "" {
		t.Errorf("Current() populated an email: %q", got.Email)
	}
}

// TestForHomeAndHomeForIDRoundTrip pins the loop the gateway depends on: a
// hook reports who it ran as, and the gateway resolves that user's profile
// from the id alone rather than trusting a hook-supplied path.
func TestForHomeAndHomeForIDRoundTrip(t *testing.T) {
	if ForHome("").Empty() != true {
		t.Fatalf("ForHome(\"\") resolved an identity")
	}

	self := Current()
	home := HomeForID(self.ID)
	if home == "" {
		t.Skipf("no profile directory resolvable for %q on this host", self.ID)
	}
	if !filepath.IsAbs(home) {
		t.Fatalf("HomeForID returned a relative path: %q", home)
	}
	owner := ForHome(home)
	if owner.ID != self.ID {
		t.Errorf("ForHome(%q).ID = %q, want %q", home, owner.ID, self.ID)
	}
}

func TestForHomeOnNonDirectoryResolvesNothing(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-profile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, path := range []string{file, filepath.Join(t.TempDir(), "missing")} {
		if got := ForHome(path); !got.Empty() {
			t.Errorf("ForHome(%q) = %+v, want empty", path, got)
		}
	}
}
