// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandboxcli

import (
	"bytes"
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestForegroundTerminalSurvivesTerminalSignals: while the child owns the
// terminal, the interrupt the terminal sends the whole foreground group
// must not end this process, and the child's own status comes back.
func TestForegroundTerminalSurvivesTerminalSignals(t *testing.T) {
	inv := openshell.Invocation{Argv: []string{"/bin/sh", "-c", "kill -INT $PPID; kill -TSTP $PPID; sleep 0.2; exit 5"}, Interactive: true}
	code, err := ForegroundTerminal{}.Run(context.Background(), inv)
	if err != nil || code != 5 {
		t.Fatalf("Run = %d, %v; want the child's exit status 5", code, err)
	}
	if _, err := (ForegroundTerminal{}).Run(context.Background(), openshell.Invocation{Argv: []string{"true"}}); err == nil {
		t.Fatal("a non-interactive invocation was run on the terminal")
	}
}

func TestCommandStreamerReportsExitStatus(t *testing.T) {
	var out bytes.Buffer
	code, err := CommandStreamer{}.Stream(context.Background(), openshell.Invocation{Argv: []string{"/bin/sh", "-c", "echo hi; exit 4"}}, &out, &out)
	if err != nil || code != 4 || out.String() != "hi\n" {
		t.Fatalf("Stream = %d, %v, %q", code, err, out.String())
	}
	if _, err := (CommandStreamer{}).Stream(context.Background(), openshell.Invocation{Argv: []string{"/nonexistent/bin"}}, &out, &out); err == nil {
		t.Fatal("a missing binary was not an error")
	}
}
