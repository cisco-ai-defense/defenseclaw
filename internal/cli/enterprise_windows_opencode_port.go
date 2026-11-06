//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

var windowsOpenCodePortClear = enterprisehooks.ClearWindowsOpenCodeContestedPort

func windowsOpenCodePortRecordPath() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	return enterprisehooks.WindowsOpenCodeServicePortsPath(layout.ManifestPath), nil
}

func windowsOpenCodePortClearCommand(port int) string {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return fmt.Sprintf("defenseclaw-gateway enterprise windows opencode-port-clear %d --yes", port)
	}
	return fmt.Sprintf("\"%s\" enterprise windows opencode-port-clear %d --yes", filepath.Join(layout.BinDir, "defenseclaw-gateway.exe"), port)
}

func newWindowsOpenCodePortClearCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:          "opencode-port-clear <port>",
		Short:        "Clear one contested OpenCode service port mark",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil || port <= 0 || port > 65535 {
				return lifecycleFlagError(cmd, fmt.Errorf("%q is not a port", args[0]))
			}
			if !yes {
				return lifecycleFlagError(cmd, errors.New("clearing a contested OpenCode port needs --yes"))
			}
			if !windowsEnterpriseIsElevated() {
				return errors.New("opencode-port-clear must run elevated")
			}
			path, err := windowsOpenCodePortRecordPath()
			if err != nil {
				return err
			}
			actor := "elevated administrator"
			if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user != nil && user.User.Sid != nil {
				actor = user.User.Sid.String()
			}
			claimants, err := windowsOpenCodePortClear(path, port, actor, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cleared the contested mark of OpenCode port %d (claimed by SIDs %s; logged in %s by %s); the guardian may give it again from its next pass\n", port, strings.Join(claimants, ", "), path, actor)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the clear")
	return cmd
}

// Status and verify report the same persisted account and contested-port
// warnings that the guardian produced. Doctor reads these warning codes.
func appendWindowsOpenCodePortWarnings(result *enterprisestatus.Result) {
	connectors, err := windowsEnterpriseEnrolledConnectors()
	if err != nil {
		return
	}
	governed := false
	for _, name := range connectors {
		if strings.EqualFold(name, "opencode") {
			governed = true
			break
		}
	}
	if !governed {
		return
	}
	path, err := windowsOpenCodePortRecordPath()
	if err != nil {
		result.AddWarning("opencode_port_record_unchecked", "cannot locate the SYSTEM-only OpenCode service ports record: "+err.Error())
		return
	}
	state, err := enterprisehooks.LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil {
		code := "opencode_port_record_unreadable"
		if !windowsEnterpriseIsElevated() {
			code = "opencode_port_record_unchecked"
		}
		result.AddWarning(code, fmt.Sprintf("OpenCode service ports record %s cannot be read (%v); inspect it in an elevated console and repair the SYSTEM-only record", path, err))
		return
	}
	for _, item := range state.Unknown {
		result.AddWarning("opencode_port_account_unknown", fmt.Sprintf("OpenCode service port for %s at %s could not be read or written as that account (%s); %s", item.SID, item.Path, item.Reason, item.Fix))
	}
	for _, mark := range state.Contested {
		result.AddWarning("opencode_port_contested", fmt.Sprintf("OpenCode service port %d is marked contested by %s; clear it with %s", mark.Port, strings.Join(mark.SIDs, ", "), windowsOpenCodePortClearCommand(mark.Port)))
	}
}
