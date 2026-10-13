//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

func acpHomePrincipalUID(_, _ string) (int, bool) { return 0, false }
