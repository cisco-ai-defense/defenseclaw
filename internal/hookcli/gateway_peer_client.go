// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func ManagedServiceName(secureClient bool) string {
	if runtime.GOOS == "linux" {
		return "defenseclaw-gateway.service"
	}
	if runtime.GOOS == "darwin" {
		if secureClient {
			return "com.cisco.secureclient.defenseclaw"
		}
		return "com.cisco.defenseclaw.gateway"
	}
	return managed.StandaloneWindowsGatewaySvc
}
