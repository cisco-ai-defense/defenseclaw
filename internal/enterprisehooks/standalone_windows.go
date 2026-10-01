//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// refuseStandaloneRootInProcess is Unix-only; Windows guardians already
// mutate profiles under the exact target token.
func refuseStandaloneRootInProcess(string) error { return nil }

// standaloneProfileProcess reports whether this process serves the
// standalone profile (the protected profile pin in its environment).
func standaloneProfileProcess() bool {
	return windowsEnterpriseStandaloneProcess()
}
