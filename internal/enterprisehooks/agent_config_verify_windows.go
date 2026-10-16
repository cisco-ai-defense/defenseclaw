// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

// The standalone Windows guardian reports a Hermes or Devin config it could
// not put back with the account's settings until they are back, as the Linux
// and macOS one does (GAP-0588); Secure Client is unchanged.
func init() {
	agentConfigReadOnVerify = WindowsStandaloneProcess
}
