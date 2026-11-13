// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "os"

// SubstrateFileOwner: Agent Substrate pods are Linux; no Windows file
// qualifies as the chart-mounted config.
func SubstrateFileOwner(os.FileInfo) (uint32, bool) { return 0, false }
