// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookuser

import (
	"bytes"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// An outage-mode look is a gateway process. When hook-user gave its answer
// and exited while a look still ran, the look ran on as an orphan, nothing
// waited for it and its result was never written, so the next call started
// another (rel-1-0-10 GAP-0268). A look now runs in its own process group,
// and every exit of hook-user stops the looks still running first; a stopped
// look gives no mode and writes no result.
var outageLooks struct {
	sync.Mutex
	exiting bool
	running map[*exec.Cmd]struct{}
}

// runOutageLook runs cmd as a look; stopped is true when hook-user stopped it
// (or was exiting before it started).
func runOutageLook(cmd *exec.Cmd) (output []byte, stopped bool, err error) {
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	outageLooks.Lock()
	if outageLooks.exiting {
		outageLooks.Unlock()
		return nil, true, nil
	}
	if err := cmd.Start(); err != nil {
		outageLooks.Unlock()
		return nil, false, err
	}
	if outageLooks.running == nil {
		outageLooks.running = map[*exec.Cmd]struct{}{}
	}
	outageLooks.running[cmd] = struct{}{}
	outageLooks.Unlock()
	err = cmd.Wait()
	outageLooks.Lock()
	delete(outageLooks.running, cmd)
	stopped = outageLooks.exiting
	outageLooks.Unlock()
	return out.Bytes(), stopped, err
}

// StopOutageLooks ends every look still running, with its process group,
// and starts no other: call it before the process exits.
func StopOutageLooks() {
	outageLooks.Lock()
	defer outageLooks.Unlock()
	outageLooks.exiting = true
	for cmd := range outageLooks.running {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
}

// ExitStoppingLooks is os.Exit for the native hook: no look outlives the call.
func ExitStoppingLooks(code int) {
	StopOutageLooks()
	os.Exit(code)
}
