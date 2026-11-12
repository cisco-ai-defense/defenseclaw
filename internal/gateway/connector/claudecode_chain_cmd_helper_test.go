// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// fakeGuardStatusEnv makes a copy of this test binary answer as the hook guard
// does: a start with the wrapped guard subcommand prints a line and exits with
// the status in the variable. The Windows tests that run the registered
// cmd.exe command line use it, so the real command processor reads the real
// wrapper (TestMain calls answerAsFakeGuard first).
const fakeGuardStatusEnv = "DEFENSECLAW_TEST_FAKE_GUARD_STATUS"

func answerAsFakeGuard() {
	if len(os.Args) < 2 || os.Args[1] != hookguard.WrappedSubcommand {
		return
	}
	status, set := os.LookupEnv(fakeGuardStatusEnv)
	if !set {
		return
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		os.Exit(125)
	}
	fmt.Print("guard-ran")
	os.Exit(code)
}
