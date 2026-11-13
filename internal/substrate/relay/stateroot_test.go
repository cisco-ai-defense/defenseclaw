// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0163: copy state goes to a 0700 folder under the relay home, never
// inside the working directory.
func TestStateRootIsOutsideTheWorkdir(t *testing.T) {
	s, _, _ := testServer(t, []string{"sh"})
	home, work := t.TempDir(), t.TempDir()
	s.opts.Config.Relay.Workdir = work
	t.Setenv("HOME", home)
	d := s.stateRoot()
	if d != filepath.Join(home, ".local", "state", "defenseclaw", "copies") {
		t.Fatalf("state root %q", d)
	}
	if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state root mode %v %v", fi, err)
	}
	// A home inside (or equal to) the working directory: no state root,
	// the launcher keeps state beside the copy.
	t.Setenv("HOME", work)
	if d := s.stateRoot(); d != "" {
		t.Errorf("home = workdir gave %q", d)
	}
	s.opts.Config.Relay.Workdir = home
	t.Setenv("HOME", filepath.Join(home, "user"))
	if d := s.stateRoot(); d != "" {
		t.Errorf("home inside the workdir gave %q", d)
	}
	// A state root others can read is not used.
	s.opts.Config.Relay.Workdir = work
	t.Setenv("HOME", home)
	_ = os.Chmod(d, 0o755)
	if got := s.stateRoot(); got != "" {
		t.Errorf("a 0755 state root was used: %q", got)
	}
}
