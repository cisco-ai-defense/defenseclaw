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
	"net"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// Interactive comfort commands (B3): port forward.

func newSubstratePortCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "port <name> <port[:local]>...",
		Short: "Open an agent's dev server in your browser (port forward)",
		Long: `Forwards a port the agent's app listens on (127.0.0.1:PORT inside the agent) to 127.0.0.1:LOCAL on this
computer, so you can open http://127.0.0.1:LOCAL in your browser. LOCAL is PORT unless you give PORT:LOCAL; when PORT
is taken here, the next free port is used. The forward listens on 127.0.0.1 only and only you can open it. It stays
in the foreground until you press Ctrl-C.

Ports 1024-65535 can be forwarded, except the relay's own port; your administrator can allow fewer or turn port
forwarding off. Every forward is recorded in the cluster's audit log. The forwarded app runs as "localhost" in your
browser, like any local dev server: open only apps you trust there.`,
		Example: "defenseclaw substrate port web-3f2a 3000\ndefenseclaw substrate port web-3f2a 3000:8000 5173",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubstratePort(cmd, &out, &com, args[0], args[1:])
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

func runSubstratePort(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, ref string, ports []string) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return err
	}
	specs := make([]attach.PortSpec, 0, len(ports))
	for _, p := range ports {
		spec, err := attach.ParsePortSpec(p)
		if err != nil {
			return cliusage.WithExitCode(err, 2)
		}
		specs = append(specs, spec)
	}
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	target := attach.Target{Atespace: a.Atespace, Name: a.Name}
	tun, err := attach.NewTunnel(ctx, attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, s.Bearer, target)
	if err != nil {
		return substrateFail(err)
	}
	defer tun.Close()
	// One stream first, so a cluster that refuses forwards says so now and
	// not at the first browser request.
	probe, err := tun.DialPort(ctx, specs[0].Remote)
	if err != nil {
		return substratePortFail(err)
	}
	_ = probe.Close()
	listeners := make([]net.Listener, 0, len(specs))
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	var lines []string
	for _, spec := range specs {
		l, err := attach.ListenPort(spec)
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		local := l.Addr().String()
		if asJSON {
			if err := writeSubstrateJSONCompact(cmd.OutOrStdout(), map[string]any{"local": local, "remote": spec.Remote}); err != nil {
				return err
			}
			continue
		}
		lines = append(lines, fmt.Sprintf("Forwarding http://%s -> %s port %d (only you, only this computer).", local, a.Name, spec.Remote))
	}
	if len(lines) > 0 {
		lines[len(lines)-1] += " Ctrl-C to stop."
		fmt.Fprintln(cmd.OutOrStdout(), strings.Join(lines, "\n"))
	}
	defer substratePresence(cmd, a)()
	var nmu sync.Mutex
	note := func(line string) {
		nmu.Lock()
		defer nmu.Unlock()
		fmt.Fprintln(cmd.ErrOrStderr(), line)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(specs))
	for i, spec := range specs {
		f := &attach.PortForward{Tunnel: tun, Spec: spec, Listener: listeners[i], Note: note}
		go func() {
			err := f.Serve(ctx)
			cancel()
			errs <- err
		}()
	}
	var first error
	for range specs {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return substratePortFail(first)
}

// substratePortFail gives a refused forward its plain message and exit code.
func substratePortFail(err error) error {
	var ref *attach.PortRefusal
	if errors.As(err, &ref) && ref.Reason != "" {
		return cliusage.WithExitCode(errors.New(ref.Error()), substrateExitRefused)
	}
	return substrateFail(err)
}
