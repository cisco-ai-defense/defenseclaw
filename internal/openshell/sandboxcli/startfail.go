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
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A harness that exits at once, before any of its hooks reached
// DefenseClaw, failed to start: the summary says so instead of blaming the
// hooks. When localhost does not resolve, the summary names it. A headless
// harness's output is kept for that; a terminal session's goes to the
// terminal only, so there one exec in the sandbox checks name resolution.

// harnessOutputBytes is how much of a headless harness's output a session
// keeps.
const harnessOutputBytes = 16 << 10

// outputTail keeps the last harnessOutputBytes written to it. stdout and
// stderr may write at once.
type outputTail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *outputTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - harnessOutputBytes; over > 0 {
		t.buf = append([]byte(nil), t.buf[over:]...)
	}
	return len(p), nil
}

func (t *outputTail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// failedAtStart reports whether the session's harness exited with an
// error, neither interrupted nor ended from outside the session, before
// any of its hooks or its telemetry reached DefenseClaw, with the daemon
// seeing nothing wrong with its hooks: the harness itself failed.
func (s *session) failedAtStart(after *sandboxapi.Sandbox, endedElsewhere bool) bool {
	code := s.harnessCode
	if s.shell || endedElsewhere || code == 0 || code == exitInterrupted || after.Hooks.Unreachable || s.hookReachUnknown(after) {
		return false
	}
	return !s.hooksReached(after) && !s.telemetryReached(after)
}

// localhostCheckScript reports whether localhost resolves through the
// sandbox's system resolver.
const localhostCheckScript = `if /usr/bin/getent hosts localhost >/dev/null 2>&1; then echo ::localhost=resolves; else echo ::localhost=unresolved; fi`

// localhostState asks the running sandbox whether localhost resolves there;
// known is false when it could not tell.
func (s *session) localhostState(ctx context.Context) (resolves, known bool) {
	inv, err := s.cli.Exec(s.sb.Name, []string{"/bin/sh", "-c", localhostCheckScript}, openshell.CLIExecOptions{Timeout: probeTimeout})
	if err != nil {
		return false, false
	}
	var out bytes.Buffer
	if code, err := s.app.Streamer.Stream(ctx, inv, &out, &out); err != nil || code != 0 {
		return false, false
	}
	for _, line := range strings.Split(out.String(), "\n") {
		state, ok := strings.CutPrefix(strings.TrimSpace(line), "::localhost=")
		if !ok {
			continue
		}
		switch state {
		case "resolves":
			return true, true
		case "unresolved":
			return false, true
		}
	}
	return false, false
}

// diagnoseStart explains, for the summary (printHookReach), a harness that
// failed at start because of localhost: why, in startWhy, and what to do,
// in startDo. The harness's output (headless) naming a failed lookup of
// localhost, or localhost not resolving in the sandbox at all, is the
// evidence; without either the summary stays as it was.
func (s *session) diagnoseStart(ctx context.Context, after *sandboxapi.Sandbox, endedElsewhere bool) {
	if !s.failedAtStart(after, endedElsewhere) || after.Phase != "ready" {
		return
	}
	line, printed := openshell.LocalhostLookupFailure(s.harnessOutput)
	resolves, known := s.localhostState(ctx)
	name := s.sb.Name
	said := "it could not resolve localhost (" + strconv.Quote(line) + ")"
	switch {
	case known && !resolves:
		s.startWhy = "localhost does not resolve in " + name
		if printed {
			s.startWhy = said + ", which does not resolve in " + name
		}
		s.startDo = "run `" + CommandName + " doctor` and check the sandbox's name resolution"
	case printed:
		s.startWhy = said
	}
}
