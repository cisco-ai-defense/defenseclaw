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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// sandboxKernelFeed is the feed's lifecycle; tests replace it.
var sandboxKernelFeed = func() *sandboxfeed.Lifecycle { return &sandboxfeed.Lifecycle{} }

// sandboxKernelFeedGOOS is the platform the commands run on (tests).
var sandboxKernelFeedGOOS = runtime.GOOS

// sandboxGatewayPath is this gateway's executable, symlinks resolved: the
// helper it installs is the one beside it, and the commands it prints name
// it by its full path (root's PATH rarely has a per-user install).
var sandboxGatewayPath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "defenseclaw-gateway"
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func newSandboxKernelFeedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kernel-feed",
		Short: "Feed Tetragon's exec records into your docker sandboxes' process trees (Linux, a root service)",
		Long: `The sandbox kernel feed is a small root service for a Linux host whose administrator runs
Tetragon: it reads Tetragon's exec and exit records of the processes in OpenShell docker sandboxes
and streams each sandbox's to its owner's DefenseClaw gateway, which adds them to the sandbox's
process tree (sandbox run --process-tree): processes that live for milliseconds are recorded too.
It only reads Tetragon (never a policy call), serves members of the docker group, and gives each
of them only their own sandboxes' records; docker-group members can already see every container,
so that filter is a courtesy, not a boundary: one of them can also add process records, real or made up,
to another account's sandbox tree. Without it the tree is the 5 s sample, as before.`,
		PersistentPreRunE: sandboxKernelFeedPreRun,
	}
	install := &cobra.Command{
		Use:   "install",
		Short: "Install or update the sandbox kernel feed service (as root; needs a unix-socket Tetragon)",
		Long: `Copies the defenseclaw-sensor-helper of this install to ` + sandboxfeed.InstalledBinary + `,
checks that this host's Tetragon serves a root-owned unix socket (never a TCP address) and that Docker
answers, then writes and starts ` + sandboxfeed.UnitName + `. Run it again after an upgrade to update
the feed. Refused on a managed host, where sandboxes are not supported.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSandboxKernelFeedInstall(cmd)
		},
	}
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the sandbox kernel feed service (as root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSandboxKernelFeedUninstall(cmd)
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether the sandbox kernel feed is installed, running and matches this gateway",
		Args:  cobra.NoArgs,
	}
	output := outputFlag(status)
	status.RunE = func(cmd *cobra.Command, _ []string) error {
		return runSandboxKernelFeedStatus(cmd, *output)
	}
	cmd.AddCommand(install, uninstall, status)
	return cmd
}

// sandboxKernelFeedPreRun replaces the sandbox commands' pre-run: these read
// no DefenseClaw configuration (install and uninstall run as root, whose
// configuration is not the user's), and run on Linux only.
func sandboxKernelFeedPreRun(*cobra.Command, []string) error {
	if sandboxKernelFeedGOOS != "linux" {
		return withExitCode(errors.New("the sandbox kernel feed is Linux only: it reads Tetragon, which runs on Linux"), 3)
	}
	return nil
}

func runSandboxKernelFeedInstall(cmd *cobra.Command) error {
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return withExitCode(errors.New("sandboxes, and so the sandbox kernel feed, are not supported in managed_enterprise deployments"), 3)
	}
	if record, present := managedHostUnixRecord(nil); present {
		return withExitCode(fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s); sandboxes, and so the sandbox kernel feed, are not supported there", record), 3)
	}
	gateway := sandboxGatewayPath()
	helper := filepath.Join(filepath.Dir(gateway), sandboxfeed.HelperName)
	result, err := sandboxKernelFeed().Install(cmd.Context(), helper, appVersion)
	if err != nil {
		if errors.Is(err, sandboxfeed.ErrNotRoot) {
			return withExitCode(fmt.Errorf("%w: sudo %s sandbox kernel-feed install", err, gateway), 1)
		}
		return err
	}
	out := cmd.OutOrStdout()
	verb := "installed"
	if result.Updated {
		verb = "updated"
	}
	fmt.Fprintf(out, "%s the sandbox kernel feed is %s (%s, protocol %d; Tetragon %s)\n",
		Style("✓", "fg=green", "bold"), verb, firstNonEmptyText(result.Version, "unknown version"), result.Protocol, result.Tetragon)
	if result.Check != "" {
		fmt.Fprintf(out, "  %s\n", result.Check)
	}
	fmt.Fprintf(out, "  sandboxes started with --process-tree (or a pack's observe.process_tree)\n  now record every exec and exit\n")
	fmt.Fprintf(out, "  check:  %s sandbox kernel-feed status\n  remove: sudo %s sandbox kernel-feed uninstall\n", gateway, gateway)
	return nil
}

func runSandboxKernelFeedUninstall(cmd *cobra.Command) error {
	gateway := sandboxGatewayPath()
	removed, err := sandboxKernelFeed().Uninstall(cmd.Context())
	if err != nil {
		if errors.Is(err, sandboxfeed.ErrNotRoot) {
			return withExitCode(fmt.Errorf("%w: sudo %s sandbox kernel-feed uninstall", err, gateway), 1)
		}
		return err
	}
	out := cmd.OutOrStdout()
	if len(removed) == 0 {
		fmt.Fprintln(out, "the sandbox kernel feed is not installed; nothing was changed")
		return nil
	}
	fmt.Fprintf(out, "%s the sandbox kernel feed is removed: %s\n", Style("✓", "fg=green", "bold"), strings.Join(removed, ", "))
	return nil
}

// sandboxKernelFeedStatus is `status --json`: the feed and the commands that
// change it.
type sandboxKernelFeedStatus struct {
	sandboxfeed.Status
	InstallCommand   string `json:"install_command"`
	UninstallCommand string `json:"uninstall_command,omitempty"`
}

func runSandboxKernelFeedStatus(cmd *cobra.Command, output string) error {
	format, err := parseOutput(output)
	if err != nil {
		return err
	}
	gateway := sandboxGatewayPath()
	report := sandboxKernelFeedStatus{
		Status:         sandboxKernelFeed().Status(cmd.Context(), appVersion),
		InstallCommand: "sudo " + gateway + " sandbox kernel-feed install",
	}
	if report.Installed {
		report.UninstallCommand = "sudo " + gateway + " sandbox kernel-feed uninstall"
	}
	if format == sandboxcli.OutputJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	printSandboxKernelFeedStatus(cmd.OutOrStdout(), report)
	return nil
}

func printSandboxKernelFeedStatus(out io.Writer, r sandboxKernelFeedStatus) {
	fmt.Fprintln(out, "Sandbox kernel feed")
	// Short lines with the next step (GAP-0034, GAP-0035); the error behind a
	// reason stays in --json (detail).
	if !r.Installed {
		fmt.Fprintf(out, "  installed:  no; install it (a unix-socket Tetragon is needed):\n      %s\n", r.InstallCommand)
	} else {
		fmt.Fprintf(out, "  installed:  yes, %s is %s\n", sandboxfeed.UnitName, firstNonEmptyText(r.Active, "unknown"))
		fmt.Fprintf(out, "  binary:     %s %s\n", r.Binary, firstNonEmptyText(r.Version, "of an unknown version"))
	}
	switch {
	case r.Reachable:
		tetragon := firstNonEmptyText(r.Tetragon, "unknown")
		if r.TetragonReason != "" {
			tetragon += " (" + r.TetragonReason + ")"
		}
		fmt.Fprintf(out, "  feed:       answers (build %s, protocol %d); its Tetragon stream is %s\n",
			firstNonEmptyText(r.Build, "unknown"), r.Protocol, tetragon)
	case r.Installed || r.Reason != sandboxfeed.ReasonNotInstalled:
		what, next := kernelFeedProblem(r.Reason)
		fmt.Fprintf(out, "  feed:       %s\n", what)
		if next != "" {
			fmt.Fprintf(out, "              %s\n", next)
		}
	}
	fmt.Fprintf(out, "  gateway:    %s, protocol %d (reads %d and %d)\n", firstNonEmptyText(r.GatewayVersion, "dev"),
		r.GatewayProtocol, r.GatewayProtocol, r.GatewayProtocol-1)
	if r.UpdateNeeded {
		fmt.Fprintf(out, "  %s the feed is older than this gateway or speaks another protocol; update it:\n      %s\n", Style("!", "fg=yellow", "bold"), r.InstallCommand)
	}
}

// kernelFeedProblem says why the feed is not read, by its reason, and what
// to do when there is something to do (next, a line of its own).
func kernelFeedProblem(reason string) (what, next string) {
	switch reason {
	case sandboxfeed.ReasonVersionSkew:
		return "not used: it speaks another protocol (" + reason + ")", ""
	case sandboxfeed.ReasonNotPermitted:
		return "not readable by this account (" + reason + ")", "join the " + sandboxfeed.DockerGroup + " group, then log in again"
	case sandboxfeed.ReasonUntrusted:
		return "refused (" + reason + ")", "its socket or folder is not root's, or others can write it"
	case sandboxfeed.ReasonUnavailable:
		return "does not answer (" + reason + ")", "sudo systemctl status " + sandboxfeed.UnitName
	case sandboxfeed.ReasonNotInstalled:
		return "no socket (" + reason + ")", ""
	}
	return "not used (" + reason + ")", ""
}

func firstNonEmptyText(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func init() {
	sandboxCmd.AddCommand(newSandboxKernelFeedCmd())
}
