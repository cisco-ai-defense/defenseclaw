// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestCertificationGatewayPeerWithoutAVCHost(t *testing.T) {
	oldExe, oldRoots := gatewayPeerExecutablePath, hookcli.WindowsManagedLayout.Roots
	oldHost, oldStandalone, oldFactory := hookcli.SecureClientHost, hookcli.ManagedHostWindowsStandalone, managedGatewayClientFactory
	t.Cleanup(func() {
		gatewayPeerExecutablePath, hookcli.WindowsManagedLayout.Roots = oldExe, oldRoots
		hookcli.SecureClientHost, hookcli.ManagedHostWindowsStandalone, managedGatewayClientFactory = oldHost, oldStandalone, oldFactory
	})
	hookcli.WindowsManagedLayout.Roots = func(profile string) (winpath.EnterpriseRoots, error) {
		return winpath.EnterpriseRootsFor(profile, `C:\Program Files`, `C:\ProgramData`)
	}
	hookcli.SecureClientHost = func() bool { return false }
	hookcli.ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
	t.Setenv("DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME", "UntrustedOtherScope")
	for _, profile := range []string{winpath.EnterpriseProfileSecureClient, winpath.EnterpriseProfileStandalone} {
		t.Run(profile, func(t *testing.T) {
			roots, _ := hookcli.WindowsManagedLayout.Roots(profile)
			gatewayPeerExecutablePath = func() (string, error) {
				return roots.CertificationInstallBase + `\f330a55401\bin\defenseclaw-gateway.exe`, nil
			}
			called := false
			managedGatewayClientFactory = func(_ time.Duration, addr, service string) (*http.Client, error) {
				called = true
				if addr != "127.0.0.1:18970" || service != "DefenseClawCertGateway_f330a55401" {
					t.Fatalf("peer = %q/%q", addr, service)
				}
				return nil, errors.New("peer proof is still required")
			}
			c := config.DefaultConfig()
			c.DeploymentMode = managed.DeploymentModeManagedEnterprise
			c.Enterprise.Profile = profile
			if _, err := gatewayPeerClient(c, "127.0.0.1", 18970, time.Second); !called || err == nil {
				t.Fatal("managed peer proof bypassed")
			}
		})
	}
	gatewayPeerExecutablePath = func() (string, error) { return "", errors.New("no executable") }
	if got := gatewayPeerServiceName(true); got != "DefenseClawGateway" {
		t.Fatalf("fallback = %q", got)
	}
	gatewayPeerExecutablePath = func() (string, error) { return `C:\Users\alice\Desktop\bin\defenseclaw-gateway.exe`, nil }
	if got := gatewayPeerServiceName(false); got != "DefenseClawGateway" {
		t.Fatalf("copied executable selected %q", got)
	}
}
