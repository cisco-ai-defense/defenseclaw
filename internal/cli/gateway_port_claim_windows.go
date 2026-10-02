// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/config"

// claimGatewayAPIPort is a Linux and macOS per-user port hint.
func claimGatewayAPIPort(*config.Config) {}
