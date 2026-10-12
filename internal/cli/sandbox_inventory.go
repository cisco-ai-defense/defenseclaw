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

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// The sandbox commands that read what runs in a sandbox: its AI inventory.

func newSandboxDiscoverCmd() *cobra.Command {
	var o sandboxcli.DiscoverOptions
	cmd := &cobra.Command{
		Use:   "discover <name>",
		Short: "Find the AI components inside a running sandbox now (MCP servers, skills, CLIs, agents)",
		Long: `Reads what the agent installed and configured inside a running sandbox (MCP servers,
skills, rules, plugins, AI CLIs and agents, environment variable names, shell history
mentions and, for a copy, package manifests) and lists the AI components found. The
daemon does this on its own once the sandbox is ready and every
ai_discovery.scan_interval_min while it runs; the AI inventory ("defenseclaw agent
usage --sandbox NAME") shows the result after its next scan.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Name, o.Output = args[0], out
			return app.Discover(ctx, o)
		}),
	}
	outputFlag(cmd)
	return cmd
}

func newSandboxPsCmd() *cobra.Command {
	var o sandboxcli.PsOptions
	cmd := &cobra.Command{
		Use:   "ps <name>",
		Short: "List the processes of a sandbox whose process tree is on",
		Long: `Lists the processes running in a sandbox whose process tree is on (a pack's
observe.process_tree: true, or "sandbox run --process-tree"): pid, parent, uptime and
command line, the values of arguments that name secrets replaced. --tree shows each
process under its parent. The daemon samples the sandbox every 5 seconds while it runs
(every 15 seconds on a Mac when sampling its MicroVM is slow) and adds what OpenShell
reports of processes starting and exiting, so a process that starts and ends between
two samples, unreported, is not seen. The agent chooses its processes' names and
arguments.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Name, o.Output = args[0], out
			return app.Ps(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().BoolVar(&o.Tree, "tree", false, "show each process under its parent")
	return cmd
}

func init() {
	sandboxCmd.AddCommand(newSandboxDiscoverCmd(), newSandboxPsCmd())
}
