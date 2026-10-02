//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

// platformHookForeignGuardSummaryDirTrusted accepts every directory on Linux
// and macOS. The summary lives in /etc/defenseclaw or
// /opt/cisco/defenseclaw/etc, where only root can create entries, and
// LoadPublicPolicy already checks the file and its ancestors, so the guard's
// behavior there is unchanged.
func platformHookForeignGuardSummaryDirTrusted(string) error { return nil }
