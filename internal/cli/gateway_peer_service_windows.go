// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

var gatewayPeerExecutablePath = os.Executable

func gatewayPeerServiceName(secureClient bool) string {
	executable, err := gatewayPeerExecutablePath()
	if err == nil {
		for _, profile := range []string{winpath.EnterpriseProfileSecureClient, winpath.EnterpriseProfileStandalone} {
			roots, err := hookcli.WindowsManagedLayout.Roots(profile)
			if err != nil {
				continue
			}
			if service := gatewayPeerServiceForExecutable(executable, roots); service != "" {
				return service
			}
		}
	}
	return hookcli.ManagedServiceName(secureClient)
}
