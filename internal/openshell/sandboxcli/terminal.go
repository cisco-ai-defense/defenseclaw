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

package sandboxcli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// ForegroundTerminal runs an interactive invocation as a child that
// inherits the terminal. While it runs, this process swallows the job
// control and interrupt signals the terminal sends to its foreground
// process group (Ctrl-C, Ctrl-Z, Ctrl-\): the child owns the terminal and
// decides what they mean, and the end-of-session review still runs after
// it exits. The signals are caught rather than ignored, so the child starts
// with the default dispositions.
type ForegroundTerminal struct{}

// Run implements Terminal.
func (ForegroundTerminal) Run(ctx context.Context, inv openshell.Invocation) (int, error) {
	if !inv.Interactive {
		return -1, errors.New("sandbox: the terminal runs interactive invocations only")
	}
	cmd, cancel, err := inv.Command(ctx)
	if err != nil {
		return -1, err
	}
	defer cancel()
	sig := make(chan os.Signal, 16)
	signal.Notify(sig, terminalSignals...)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range sig {
		}
	}()
	err = cmd.Run()
	signal.Stop(sig)
	close(sig)
	<-drained
	return exitStatus(err)
}

// CommandStreamer runs a non-interactive invocation with its output on the
// given writers.
type CommandStreamer struct{}

// Stream implements Streamer.
func (CommandStreamer) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if inv.Interactive {
		return -1, errors.New("sandbox: interactive invocations need the terminal")
	}
	cmd, cancel, err := inv.Command(ctx)
	if err != nil {
		return -1, err
	}
	defer cancel()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return exitStatus(cmd.Run())
}

// exitStatus turns a finished command's error into its exit status; only
// failures to run at all are errors.
func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			return code, nil
		}
		return 128 + signalNumber(exit), nil
	}
	return -1, err
}
