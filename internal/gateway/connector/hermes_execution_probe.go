// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const hermesExecutionProbeResponse = "defenseclaw-execution-probe-ok\n"

// hermesExecutionProbeTimeout bounds one probe run; tests shorten it.
// hermesExecutionProbePipeWait bounds the wait for stdout to close after the
// probe exits or is killed: a descendant that inherited stdout cannot hold
// Verify open.
//
// The first run of a launcher an upgrade has just replaced waits for the
// antivirus scan of its image: 2.8 s for the 130 MB Windows defenseclaw-hook.exe
// on an idle host, so the earlier 3 s bound failed the upgrade's Verify on a
// busy one (GAP-0837).
var (
	hermesExecutionProbeTimeout  = 10 * time.Second
	hermesExecutionProbePipeWait = time.Second
)

// hermesRegisteredCommandExecutable probes only the target Setup computed.
// ownedHooksPresentInConfig has already read back the exact agent registration,
// so an edited command cannot make Verify execute an arbitrary program.
func hermesRegisteredCommandExecutable(opts SetupOpts, hookCommand string) bool {
	executable := hermesHookExecutable(runtime.GOOS, opts)
	target := hermesHookExecutablePath(hookCommand, executable)
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	args := []string{"--defenseclaw-execution-probe"}
	if runtime.GOOS == "windows" {
		// Probe the registered native command through its launcher and hook
		// runtime. A disabled launcher can return success without delegating;
		// only the active hook runtime emits the proof response.
		if !strings.EqualFold(filepath.Ext(target), ".exe") ||
			windowsHermesDirectHookCommand(executable) != hookCommand {
			return false
		}
		args = []string{"hook", "--connector", "hermes", "--defenseclaw-execution-probe"}
	} else {
		if info.Mode().Perm()&0o111 == 0 {
			return false
		}
		if runtime.GOOS == "darwin" {
			args = append(args, "--forkless")
		}
	}
	return runHermesExecutionProbe(target, args)
}

// runHermesExecutionProbe keeps no more stdout than the proof itself: one
// byte more fails the write, which closes the pipe and ends the probe.
// RunContained ends the process tree when the probe exits and at the
// timeout (a Job Object on Windows, a PID namespace on Linux, a
// forkless launcher plus process group and lifeline on macOS) and fails the
// proof when it cannot
// establish that nothing the hook started still runs: a hook that started a
// child in a session of its own passed while the child kept running (r104
// W5b). Stdout left open by a descendant is closed after
// hermesExecutionProbePipeWait.
func runHermesExecutionProbe(target string, args []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), hermesExecutionProbeTimeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, target, args...)
	stdout := &hermesBoundedCommandBuffer{limit: int64(len(hermesExecutionProbeResponse))}
	cmd.Stdout = stdout
	cmd.WaitDelay = hermesExecutionProbePipeWait
	err := processutil.RunContained(cmd)
	return err == nil && stdout.String() == hermesExecutionProbeResponse
}
