// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-2242: Windows normalizes a path by name before it opens it,
// so a dot-dot step after a junction or after a name that is not there leads
// back into the folder that holds it. J\..\.ssh\* (J a junction to a folder
// outside the profile) and nosuch\..\.ssh\* name the profile's .ssh folder
// and reach its authorized keys files as .ssh\* does. Before the fix the step
// out of a link or a missing name kept the spelling (POSIX semantics), so an
// empty .ssh read as not reached.
func TestGAP2242DotDotAfterJunctionOrMissingNameStepsByName(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	makeProjectSkillJunction(t, filepath.Join(home, "J"), t.TempDir())
	protected := newProtectedFiles(home)
	for _, base := range []string{`.ssh\*`, `.ssh\authorized_key?`, `.ssh\.\*`} {
		if !actionProtectedFileGlobReachAs(base, home, protected, ssh, home, nil, true, true) {
			t.Fatalf("%q from the profile does not reach the authorized keys files", base)
		}
		for _, prefix := range []string{`J\..\`, `nosuch\..\`, `J\nosuch\..\..\`, `.\J\..\`} {
			if !actionProtectedFileGlobReachAs(prefix+base, home, protected, ssh, home, nil, true, true) {
				t.Errorf("%q from the profile is not reached, %q is", prefix+base, base)
			}
		}
	}
}
