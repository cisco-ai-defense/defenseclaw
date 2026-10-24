// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package processutil

import (
	"os/exec"
	"runtime"
)

func configureCapturedCommand(_ *exec.Cmd) {}

func combinedOutputTree(cmd *exec.Cmd, _ bool) ([]byte, error) {
	return cmd.CombinedOutput()
}

// runTree runs cmd on a thread locked to this goroutine until it is reaped:
// Linux sends the parent-death signal when the thread that started the child
// ends, not the process, so the runtime must not end that thread while the
// child still runs (G-small).
func runTree(cmd *exec.Cmd, _ bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	exitWithParent(cmd)
	err := cmd.Start()
	if err != nil {
		return err
	}
	killDescendantsAtExit(cmd)
	return cmd.Wait()
}
