// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "context"

func trustedNativeGatewayRecovery() func(context.Context, error) error { return nil }

// perUserGatewayRecovery is Windows only: the Linux and macOS shell hooks
// start a per-user gateway themselves (defenseclaw_gateway_cold_start).
func perUserGatewayRecovery() func(context.Context, error) error { return nil }
