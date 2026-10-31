// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "github.com/defenseclaw/defenseclaw/internal/sensor"

// aiRuntimeSpoolAccounts adds nothing on Windows: the AI Discovery scan's
// profile list (HKLM ProfileList) is the enrolled-account table there.
var aiRuntimeSpoolAccounts = func() []sensor.Account { return nil }
