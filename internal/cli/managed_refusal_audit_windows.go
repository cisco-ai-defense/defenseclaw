// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// managedRefusalReportBudget bounds a refusal report: the refusal itself
// never waits for the gateway.
const managedRefusalReportBudget = 500 * time.Millisecond

// reportManagedCommandRefusal reports a command refused on a managed Windows
// computer on the gateway's refusal pipe, which names the account from the
// pipe client's token: a standard account's refusals left no audit row
// (GAP-2639). Only the command's fixed words and the reason are sent. It is
// best effort; the refusal does not depend on it.
var reportManagedCommandRefusal = func(command, reason string) {
	if _, managed := managedHostWindowsStandalone(); !managed {
		return
	}
	if reason == "" {
		reason = refusalpipe.ReasonManagedDevice
	}
	ctx, cancel := context.WithTimeout(context.Background(), managedRefusalReportBudget)
	defer cancel()
	_ = refusalpipe.Send(ctx, refusalpipe.Report{Command: command, Reason: reason})
}
