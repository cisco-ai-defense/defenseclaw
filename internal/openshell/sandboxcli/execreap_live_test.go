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

//go:build openshell_integration

package sandboxcli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// TestLiveExecClientEndStopsTheCommand runs against a ready sandbox on the
// local OpenShell gateway (DC_OPENSHELL_EXEC_SANDBOX names it): a `sandbox
// exec` whose client is killed leaves its command running in OpenShell
// 0.1.1, and the reaper stops it, its children included.
// DC_OPENSHELL_EXEC_NO_WRAPPER runs the command without the image's
// sandbox-env wrapper (an image built before it).
func TestLiveExecClientEndStopsTheCommand(t *testing.T) {
	sandbox := os.Getenv("DC_OPENSHELL_EXEC_SANDBOX")
	if sandbox == "" {
		t.Skip("DC_OPENSHELL_EXEC_SANDBOX names no sandbox")
	}
	cli := openshell.CLI{Binary: "openshell", Gateway: firstNonEmpty(os.Getenv("DC_OPENSHELL_GATEWAY"), "openshell")}
	session, err := newExecSession()
	if err != nil {
		t.Fatal(err)
	}
	// A sleep of an unusual length, to be counted in the sandbox.
	sleep := fmt.Sprintf("sleep %d", 600+time.Now().Second())
	command := []string{"/bin/sh", "-c", sleep + " & wait"}
	if os.Getenv("DC_OPENSHELL_EXEC_NO_WRAPPER") == "" {
		command = append([]string{harness.SandboxEnvPath}, command...)
	}
	inv, err := cli.Exec(sandbox, execSessionArgv(session, command), openshell.CLIExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, stop, err := inv.Command(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var cmdOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &cmdOut, &cmdOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// running counts the session shell (by its mark) and the sleep below it.
	running := func() (shells, sleeps int) {
		t.Helper()
		probe, err := cli.Exec(sandbox, []string{"/bin/sh", "-c",
			`s=0; z=0; for p in /proc/[0-9]*; do [ "$p" = "/proc/$$" ] && continue; c="$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)"; ` +
				`case "$c" in *"$1"*) s=$((s+1));; esac; [ "$c" = "$2 " ] && z=$((z+1)); done; echo "$s $z"`,
			"probe", " " + execSessionMark + session + " ", sleep}, openshell.CLIExecOptions{Timeout: 30 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if _, err := (CommandStreamer{}).Stream(context.Background(), probe, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(out.String())
		if len(f) != 2 {
			t.Fatalf("probe output %q", out.String())
		}
		shells, _ = strconv.Atoi(f[0])
		sleeps, _ = strconv.Atoi(f[1])
		return shells, sleeps
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		shells, sleeps := running()
		if shells >= 1 && sleeps == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the command never ran in the sandbox (%d shells, %d sleeps): %s", shells, sleeps, cmdOut.String())
		}
		time.Sleep(time.Second)
	}
	// The client ends; OpenShell 0.1.1 leaves the command running.
	cancel()
	_ = cmd.Wait()
	time.Sleep(2 * time.Second)
	shells, sleeps := running()
	t.Logf("after the client ended: %d session shells, %d sleeps still run", shells, sleeps)
	a := &App{Streamer: CommandStreamer{}}
	a.defaults()
	a.reapExec(context.Background(), cli, sandbox, session)
	if shells, sleeps := running(); shells != 0 || sleeps != 0 {
		t.Fatalf("after the reaper: %d session shells, %d sleeps still run", shells, sleeps)
	}
}
