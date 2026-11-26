// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/hookcli"

func gatewayPeerServiceName(secureClient bool) string {
	return hookcli.ManagedServiceName(secureClient)
}
