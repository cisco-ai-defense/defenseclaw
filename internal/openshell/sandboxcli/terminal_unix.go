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
	"os"
	"os/exec"
	"syscall"
)

// terminalSignals are what the terminal sends the foreground job.
var terminalSignals = []os.Signal{syscall.SIGINT, syscall.SIGTSTP, syscall.SIGQUIT}

// forwardedSignals end the interactive harness rather than this process:
// the terminal hung up, or something asked this process to terminate.
var forwardedSignals = []os.Signal{syscall.SIGHUP, syscall.SIGTERM}

// sessionSignals end a headless harness run rather than this process.
var sessionSignals = []os.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM}

func signalNumber(exit *exec.ExitError) int {
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return int(ws.Signal())
	}
	return 0
}

// execProcess replaces this process with path.
func execProcess(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}
