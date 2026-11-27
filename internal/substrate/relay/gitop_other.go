// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package relay

import (
	"context"
	"fmt"
	"io"
)

// Actors are Linux: a relay elsewhere is never separated, so the launcher
// runs the in-actor review and push scripts.
func runGitOp(_ context.Context, _ []string, _ string, _ map[string]string, _ *separation, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, "the relay runs as the agent's user")
	return ExitGitUnseparated
}
