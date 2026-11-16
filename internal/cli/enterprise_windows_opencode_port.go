//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

var windowsOpenCodePortClear = enterprisehooks.ClearWindowsOpenCodeContestedPort
var windowsOpenCodePortWarningRead = readWindowsOpenCodePortWarnings
var windowsOpenCodePortConnectorList = windowsEnterpriseEnrolledConnectors

const windowsOpenCodePortWarningsFile = "opencode_port_warnings.json"

type windowsOpenCodePortWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type windowsOpenCodePortWarningRecord struct {
	Version  int                          `json:"version"`
	Warnings []windowsOpenCodePortWarning `json:"warnings"`
}

func windowsOpenCodePortWarningsPath() (string, error) {
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		return "", err
	}
	return filepath.Join(layout.DataDir, windowsOpenCodePortWarningsFile), nil
}

// The port record remains SYSTEM-only. The guardian publishes just warning
// text under the existing admin-readable guardian-state ACL for lifecycle
// status and doctor; it contains no bindings or account file contents.
func writeWindowsOpenCodePortWarnings(state enterprisehooks.WindowsOpenCodeServicePortsState) error {
	var warnings []windowsOpenCodePortWarning
	for _, item := range state.Unknown {
		warnings = append(warnings, windowsOpenCodePortWarning{Code: "opencode_port_account_unknown", Message: fmt.Sprintf("OpenCode service port for %s at %s could not be read or written as that account (%s); %s", item.SID, item.Path, item.Reason, item.Fix)})
	}
	for _, mark := range state.Contested {
		message := fmt.Sprintf("OpenCode service port %d is marked contested by %s; clear it with %s", mark.Port, strings.Join(mark.SIDs, ", "), windowsOpenCodePortClearCommand(mark.Port))
		if len(mark.SIDs) == 1 {
			message = fmt.Sprintf("OpenCode service port %d remains held because %s's file could not be replaced in the import pass; repair the account file, then clear the held mark with %s", mark.Port, mark.SIDs[0], windowsOpenCodePortClearCommand(mark.Port))
		}
		warnings = append(warnings, windowsOpenCodePortWarning{Code: "opencode_port_contested", Message: message})
	}
	return writeWindowsOpenCodePortWarningItems(warnings)
}

func writeWindowsOpenCodePortWarningItems(warnings []windowsOpenCodePortWarning) error {
	path, err := windowsOpenCodePortWarningsPath()
	if err != nil {
		return err
	}
	record := windowsOpenCodePortWarningRecord{Version: 1, Warnings: warnings}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("OpenCode port warning summary is too large")
	}
	return writeEnterpriseHookProtectedFile(path, append(data, '\n'))
}

func readWindowsOpenCodePortWarnings() ([]windowsOpenCodePortWarning, error) {
	path, err := windowsOpenCodePortWarningsPath()
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("OpenCode port warning summary is not a regular file")
	}
	if err := enterpriseHookGuardianStateFileTrustCheck(path); err != nil {
		return nil, err
	}
	data, err := readWindowsEnterpriseBoundedFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var record windowsOpenCodePortWarningRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if record.Version != 1 || len(record.Warnings) > 256 {
		return nil, errors.New("OpenCode port warning summary has invalid schema")
	}
	for _, warning := range record.Warnings {
		switch warning.Code {
		case "opencode_port_account_unknown", "opencode_port_contested", "opencode_port_record_unreadable":
		default:
			return nil, errors.New("OpenCode port warning summary has an invalid code")
		}
	}
	return record.Warnings, nil
}

func windowsOpenCodePortRecordPath() (string, error) {
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		return "", err
	}
	return enterprisehooks.WindowsOpenCodeServicePortsPath(layout.ManifestPath), nil
}

// windowsOpenCodePortClearCommand is the command an administrator types in
// PowerShell to clear one contested OpenCode port mark: the installed gateway
// by its full path, rendered like every managed Windows command.
func windowsOpenCodePortClearCommand(port int) string {
	return managedWindowsGatewayCommandLine("enterprise", "windows", "opencode-port-clear", strconv.Itoa(port), "--yes")
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
	connectors, err := windowsOpenCodePortConnectorList()
	if err != nil {
		result.AddWarning("opencode_port_record_unchecked", "OpenCode port warning status could not be checked because the installed connector list is unavailable: "+err.Error())
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
	warnings, err := windowsOpenCodePortWarningRead()
	if err != nil {
		result.AddWarning("opencode_port_record_unchecked", fmt.Sprintf("OpenCode port warnings could not be checked (%v); inspect the guardian state in an elevated console", err))
		return
	}
	for _, warning := range warnings {
		result.AddWarning(warning.Code, warning.Message)
	}
}
