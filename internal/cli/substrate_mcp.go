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

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/substrate/launcherpresence"
)

// Laptop MCP servers (B3.3, Preview): `substrate run|connect --mcp NAME=CMD`.
// --mcp is an action of this one run, not a setting: no config key and no
// environment variable gives it a value.

const substrateMCPFlagHelp = "(Preview) start COMMAND on this computer and offer it to the agent as the MCP server NAME while this command is attached (repeatable)"

// substrateMCPWait is how long a stream that only waits for the agent's relay
// to come up is retried.
const substrateMCPWait = 30 * time.Second

// substrateMCPSpecs reads the --mcp values before anything is dialed.
// Mistakes in them are usage errors (exit 2).
func substrateMCPSpecs(vals []string, detach, batch bool) ([]attach.MCPSpec, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	if detach || batch {
		return nil, cliusage.WithExitCode(errors.New("--mcp lasts while this command is attached, so it does not go with --detach or --batch"), 2)
	}
	specs, err := attach.ParseMCPSpecs(vals)
	if err != nil {
		return nil, cliusage.WithExitCode(err, 2)
	}
	return specs, nil
}

// substrateMCPRun is the open bridges of one run or connect. Its methods
// accept a nil receiver, the case of no --mcp.
type substrateMCPRun struct {
	bridges *attach.MCPBridges
	asked   int
	notices chan string
}

// Notices is the channel for attach.Options.Notices: lines to show on the
// launcher's row while the terminal is attached.
func (m *substrateMCPRun) Notices() <-chan string {
	if m == nil {
		return nil
	}
	return m.notices
}

// AllRefused reports that servers were asked for and none could be bridged.
func (m *substrateMCPRun) AllRefused() bool { return m != nil && m.asked > 0 && m.bridges.Opened == 0 }

// Close ends every stream and kills every child.
func (m *substrateMCPRun) Close() {
	if m != nil {
		m.bridges.Close()
	}
}

// startSubstrateMCP opens the stream of every server and returns once each
// is open or refused; a refusal prints its line and the run goes on. With
// interactive, lines after that go to the launcher's row (the agent's
// terminal is in use); otherwise they go to stderr.
func startSubstrateMCP(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, specs []attach.MCPSpec, interactive bool) (*substrateMCPRun, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	tun, err := attach.NewTunnel(ctx, attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, s.Bearer, attach.Target{Atespace: a.Atespace, Name: a.Name})
	if err != nil {
		return nil, substrateFail(err)
	}
	m := &substrateMCPRun{asked: len(specs), notices: make(chan string, 32)}
	var (
		mu   sync.Mutex
		live atomic.Bool
	)
	note := func(line string) {
		if live.Load() {
			select {
			case m.notices <- line:
			default:
			}
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintln(cmd.ErrOrStderr(), line)
	}
	rec := substrateRecord(cmd, a)
	m.bridges = attach.StartMCPBridges(ctx, attach.MCPBridgeOptions{
		Tunnel: tun, Specs: specs, Note: note, Wait: substrateMCPWait,
		OnChild: func(name string, pid int) func() {
			remove, _ := launcherpresence.WriteBridge(auth.StateDir(), rec, pid, name)
			return remove
		},
	})
	if interactive {
		live.Store(true)
	}
	if m.bridges.Opened > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "Bridging %d of %d laptop MCP server(s) to %s while this command is attached.\n", m.bridges.Opened, len(specs), a.Name)
	}
	return m, nil
}

// substrateMCPNone is the end of a --task run in which no server could be
// bridged: the task ran without them, and the exit code says so.
func substrateMCPNone(m *substrateMCPRun, names []attach.MCPSpec) error {
	if !m.AllRefused() {
		return nil
	}
	list := make([]string, 0, len(names))
	for _, n := range names {
		list = append(list, n.Name)
	}
	return cliusage.WithExitCode(fmt.Errorf("none of the requested MCP servers (%s) could be bridged; the task ran without them", strings.Join(list, ", ")), 1)
}
