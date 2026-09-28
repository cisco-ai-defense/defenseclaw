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

//go:build linux || darwin

package sandboxcli

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestForegroundTerminalRestoresTheTerminalMode: a harness that puts the
// terminal in raw mode and dies without undoing it (here SIGKILL) leaves it
// cooked again for the end-of-session prompts, which read lines ended by
// Enter and stop on Ctrl-C.
func TestForegroundTerminalRestoresTheTerminalMode(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("no stty")
	}
	_, slave := openPTY(t)
	cooked := func() bool {
		tio, err := unix.IoctlGetTermios(int(slave.Fd()), ioctlGetTermios)
		if err != nil {
			t.Fatal(err)
		}
		const want = unix.ICANON | unix.ECHO | unix.ISIG
		return tio.Lflag&want == want
	}
	if !cooked() {
		t.Fatal("a new pseudo-terminal is not in cooked mode")
	}
	// The child inherits this process's stdin (openshell.Invocation).
	stdin := os.Stdin
	os.Stdin = slave
	defer func() { os.Stdin = stdin }()
	inv := openshell.Invocation{Interactive: true, Argv: []string{"/bin/sh", "-c", "stty raw -echo && kill -KILL $$"}}
	code, err := ForegroundTerminal{}.Run(context.Background(), inv)
	if err != nil || code != 128+int(syscall.SIGKILL) {
		t.Fatalf("Run = %d, %v; want the child killed", code, err)
	}
	if !cooked() {
		t.Fatal("the terminal was left in the raw mode the killed child set")
	}
}
