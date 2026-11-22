//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

func trustedActiveShell(context.Context) string { return "" }
