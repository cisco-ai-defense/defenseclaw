// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

func init() {
	managedWindowsRemovedConnectorLines = ownRemovedConnectorLines
}

// ownRemovedConnectorLines reads the caller's own status from the gateway's
// own-status pipe and names each connector it reports as removed from the
// roster. Any failure, and a caller that is not a standard account, gives none:
// the doctor and TUI answers then say what they always said.
func ownRemovedConnectorLines() []string {
	if !statusShowsOwnState() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, err := ownStatusPipeFetch(ctx)
	if err != nil {
		return nil
	}
	return removedConnectorLinesFromOwnStatus(body)
}

// removedConnectorLinesFromOwnStatus lists the connectors of an own-status
// answer whose state is managed.NotManagedRemovedFromRoster, sorted.
func removedConnectorLinesFromOwnStatus(body []byte) []string {
	var view struct {
		Connectors map[string]struct {
			State string `json:"state"`
		} `json:"connectors"`
	}
	if json.Unmarshal(body, &view) != nil {
		return nil
	}
	var lines []string
	for name, row := range view.Connectors {
		if row.State == managed.NotManagedRemovedFromRoster {
			lines = append(lines, name+": "+managed.NotManagedRemovedFromRoster)
		}
	}
	sort.Strings(lines)
	return lines
}

// newLauncherStatusCommand is nil: Windows has no launcher.
func newLauncherStatusCommand() *cobra.Command { return nil }

// ownStatusPipeFetch asks the managed gateway service on its own-status
// pipe for the caller's own protection state; a seam for tests.
var ownStatusPipeFetch = refusalpipe.OwnStatus

// statusShowsOwnState reports whether `defenseclaw status` shows the
// caller's own protection state: a standard account of a Windows standalone
// managed computer, which has no per-user gateway and may not read the
// managed one, was refused and could not see whether its Claude Code and
// Cowork were protected (cowork-1-0-8 GAP-0060). The gateway service names
// the account from the pipe client token and answers with that account's
// state only. An elevated administrator keeps the answer that names the
// administrator's checks, and a caller that named a config, or the managed
// service itself, keeps the gateway status. A seam for tests.
var statusShowsOwnState = func() bool {
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) ||
		strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" || windowsEnterpriseIsElevated() {
		return false
	}
	_, present := managedHostWindowsStandalone()
	return present
}

// readOwnStatus reads the caller's own state from the gateway service's
// own-status pipe (refusalpipe.OwnStatus).
func readOwnStatus(ctx context.Context) ([]byte, error) {
	body, err := ownStatusPipeFetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("the managed gateway service did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
	}
	return body, nil
}

// ownStatusNextSteps names the administrator's view of this account's
// agents: a standard account of a managed Windows computer has no other
// view of its own.
func ownStatusNextSteps() []string {
	return []string{"Your administrator sees your account's agents from an elevated PowerShell prompt with " +
		managedWindowsAccountAgentsCommand() + "."}
}
