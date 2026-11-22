// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TaskFaultsEnv names the file in which the hooks of a --task run record
// each call the cluster gateway did not answer (GAP-0326). The relay creates
// the file before it starts the agent and reads it when the agent exits: a
// hook that failed closed in an outage refused a step the agent was asked to
// run, so an agent that still exits 0 has not done its task, and the relay
// must not report it as a success. The agent can only add lines (its own run
// then fails) or remove the file (the relay then reports the agent's exit,
// as before).
const TaskFaultsEnv = "DEFENSECLAW_TASK_FAULTS"

// taskFaultsMax bounds what the relay reads of the file.
const taskFaultsMax = 64 << 10

// TaskFault is one hook call of a task run that the gateway did not answer.
type TaskFault struct {
	At    string // RFC 3339, UTC
	Event string // the hook event, for example PostToolUse
}

// recordTaskFault appends one line to the run's fault file, when the run has
// one. The file must exist (the relay made it): a hook outside a task run,
// or one given a path that is not there, writes nothing.
func recordTaskFault(getenv func(string) string, event string, now time.Time) {
	p := strings.TrimSpace(getenv(TaskFaultsEnv))
	if p == "" || !filepath.IsAbs(p) {
		return
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", now.UTC().Format(time.RFC3339), faultWord(event))
}

// faultWord is an event name fit for one field of a line: letters, digits,
// '-' and '_', at most 64 of them; "unknown" when nothing is left.
func faultWord(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// ReadTaskFaults counts the faults recorded in the file at path and returns
// the first. A missing or unreadable file has none.
func ReadTaskFaults(path string) (int, TaskFault) {
	f, err := os.Open(path)
	if err != nil {
		return 0, TaskFault{}
	}
	defer f.Close()
	n, first := 0, TaskFault{}
	sc := bufio.NewScanner(io.LimitReader(f, taskFaultsMax))
	for sc.Scan() {
		at, event, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		if _, err := time.Parse(time.RFC3339, at); err != nil {
			continue
		}
		if n == 0 {
			first = TaskFault{At: at, Event: faultWord(event)}
		}
		n++
	}
	return n, first
}
