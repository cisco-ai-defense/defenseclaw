// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// On macOS the sandbox daemon leaves by itself when idle while the gateway
// agent stays loaded, so an account whose daemon is gone but whose gateway
// runs is asked through the launcher (which starts the daemon): a switch or a
// stop must not stop a gateway that hosts sandboxes on a guess.
func TestCommandOpsMacOSGatewayRunsWithoutTheDaemon(t *testing.T) {
	running := func(count string) func(string) (CommandResult, error) {
		return func(line string) (CommandResult, error) {
			switch {
			case line == "launchctl print gui/1001":
				return CommandResult{}, errors.New("not found")
			case strings.HasPrefix(line, "launchctl print user/1001/com.cisco.defenseclaw.openshell-gateway"):
				return CommandResult{Stdout: []byte("state = running\n")}, nil
			case strings.HasPrefix(line, "launchctl print user/1001/com.cisco.defenseclaw.sandbox"):
				return CommandResult{Stdout: []byte("state = waiting\n")}, nil
			case strings.HasSuffix(line, "sandbox status --output json"):
				if count == "" {
					return CommandResult{}, errors.New("the daemon did not start")
				}
				return CommandResult{Stdout: []byte(`{"running":` + count + `}`)}, nil
			}
			return CommandResult{}, nil
		}
	}
	ops, runner, alice := opsHost(t, "darwin", running("3"))
	st, err := ops.Status(context.Background(), alice)
	if err != nil || !st.Active || st.Running != 3 || !runner.called("sandbox status --output json") {
		t.Fatalf("Status = %+v %v after %v", st, err, runner.calls)
	}
	failing, _, alice2 := opsHost(t, "darwin", running(""))
	if _, err := failing.Status(context.Background(), alice2); err == nil {
		t.Fatal("a gateway that runs while the daemon does not answer reads as idle")
	}
	// Neither agent running: nothing is asked, nothing runs.
	idle, idleRunner, alice3 := opsHost(t, "darwin", func(line string) (CommandResult, error) {
		if strings.HasPrefix(line, "launchctl print user/") {
			return CommandResult{Stdout: []byte("state = waiting\n")}, nil
		}
		return CommandResult{}, errors.New("not found")
	})
	if st, err := idle.Status(context.Background(), alice3); err != nil || st.Active || idleRunner.called("sandbox status") {
		t.Fatalf("idle account: Status = %+v %v after %v", st, err, idleRunner.calls)
	}
}
