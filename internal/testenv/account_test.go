// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"testing"
)

func TestIsolateAccountMovesTheHomeAndClearsTheAccountEnvironment(t *testing.T) {
	for _, name := range accountEnv {
		t.Setenv(name, "/real/"+name)
	}
	realHome := os.Getenv("HOME")
	t.Run("isolated", func(t *testing.T) {
		home := IsolateAccount(t)
		if got := os.Getenv("HOME"); got != home || got == realHome {
			t.Fatalf("HOME = %q, want the new home %q (was %q)", got, home, realHome)
		}
		for _, name := range accountEnv {
			if value, set := os.LookupEnv(name); set {
				t.Errorf("%s is still set to %q", name, value)
			}
		}
	})
	if got := os.Getenv("DEFENSECLAW_HOME"); got != "/real/DEFENSECLAW_HOME" {
		t.Fatalf("DEFENSECLAW_HOME not restored after the test: %q", got)
	}
}
