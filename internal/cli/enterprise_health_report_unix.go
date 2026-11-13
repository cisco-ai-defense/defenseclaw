// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// macOSSecureClientDataDir is the Secure Client gateway's data_dir on macOS,
// where it writes diagnostics/health_report_last.json.
const macOSSecureClientDataDir = "/opt/cisco/secureclient/defenseclaw/runtime"

// Seams for tests.
var (
	secureClientHealthReportDataDir = func() string { return macOSSecureClientDataDir }
	healthReportReaderIsRoot        = func() bool { return os.Geteuid() == 0 }
)

// attachSecureClientHealthReport adds the health_report block to a macOS
// status run as root on a Secure Client host, whose gateway runs the endpoint
// health reporter. The block is omitted when there is no report, and never
// changes ok or the exit code. Other hosts and actions are left as they are.
func attachSecureClientHealthReport(result *enterprisestatus.Result, goos string, now time.Time) {
	if result == nil || goos != "darwin" || result.Action != enterpriseunix.ActionStatus || result.PendingApply ||
		lifecycleResultHasError(result, "not_root") || !healthReportReaderIsRoot() || !secureClientHost() {
		return
	}
	result.SetHealthReport(enterprisestatus.ReadHealthReport(secureClientHealthReportDataDir(), now))
}
