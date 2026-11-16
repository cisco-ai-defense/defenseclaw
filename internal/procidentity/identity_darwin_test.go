// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procidentity

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The macOS record is what `LC_ALL=C TZ=UTC ps -o lstart=` prints, the
// reader the shell hooks, install.sh, both plugins and doctor use.
func TestOfIsPsLstartInTheCLocaleAndUTC(t *testing.T) {
	for _, pid := range []int{os.Getpid(), os.Getppid(), 1} {
		identity, ok := Of(pid)
		if !ok {
			t.Fatalf("no identity for pid %d", pid)
		}
		cmd := exec.Command("/bin/ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
		cmd.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/usr/bin:/bin"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Join(strings.Fields(string(out)), " "); identity != want {
			t.Fatalf("Of(%d) = %q, ps lstart = %q", pid, identity, want)
		}
	}
}
