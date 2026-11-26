// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

var perUserGatewayClientFactory = hookexec.NewPerUserGatewayHTTPClient

// managedGatewayClientFactory waits out a managed gateway that runs but is
// not listening yet: a scan right after secret set restarted the gateway
// failed at once with "running service has no listener yet" (GAP-2442).
var managedGatewayClientFactory = func(timeout time.Duration, apiAddr, serviceName string) (*http.Client, error) {
	return hookexec.NewManagedEnterpriseGatewayHTTPClientAwaitingStart(timeout, apiAddr, serviceName, managedGatewayStartBudget)
}

// managedGatewayStartBudget bounds how long a CLI command waits for a
// starting managed gateway to listen.
const managedGatewayStartBudget = 30 * time.Second

// gatewayPeerClient is the transport for Go CLI requests to the local
// gateway. The owner of the connected socket is checked after Dial, before
// net/http can send a token, scan target, or telemetry fact: this account
// for a per-user gateway, the gateway service for a managed one. While a
// gateway restarts another account can bind its port; it receives nothing.
func gatewayPeerClient(c *config.Config, host string, port int, timeout time.Duration) (*http.Client, error) {
	if c != nil && c.SecureClientIntegration() && hookcli.SecureClientHost() {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), gatewayPeerServiceName(true))
	}
	if _, present := hookcli.ManagedHostWindowsStandalone(); present &&
		(c == nil || c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), gatewayPeerServiceName(false))
	}
	// The administrator's scan on a managed Linux or macOS computer loads no
	// config (GAP-1234): the managed deployment record names the gateway
	// service, which runs as its own account, not the caller's.
	if c == nil && runtime.GOOS != "windows" {
		if _, present := managedHostUnixRecord(nil); present {
			return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), gatewayPeerServiceName(false))
		}
	}
	if c != nil && (c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), gatewayPeerServiceName(false))
	}
	return perUserGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)))
}

func gatewayPeerClientForURL(c *config.Config, rawURL string, timeout time.Duration) (*http.Client, error) {
	host, port, err := localGatewayURLEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	return gatewayPeerClient(c, host, port, timeout)
}

func localGatewayURLEndpoint(rawURL string) (string, int, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Hostname() == "" {
		return "", 0, fmt.Errorf("gateway target is not a local HTTP endpoint")
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("gateway target port is invalid")
	}
	return target.Hostname(), port, nil
}

// gatewayPeerServiceForExecutable recognizes only the binary's exact protected
// production or certification install root. Environment pins cannot select a
// different scope's peer. winpath also recognizes versioned hook launch bins.
func gatewayPeerServiceForExecutable(executable string, roots winpath.EnterpriseRoots) string {
	bin := winpath.EnterpriseInstallBinOf(executable)
	if bin == "" {
		return ""
	}
	service, err := winpath.EnterpriseGatewayServiceForRoot(roots, bin[:len(bin)-len(`\bin`)])
	if err != nil {
		return ""
	}
	return service
}
