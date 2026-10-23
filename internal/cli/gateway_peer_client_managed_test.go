// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0962: while a managed gateway is down another account can bind its API
// port. A CLI request (here a scan with the administrator's bearer) must not
// reach that listener: the managed client proves the gateway service owns the
// connected socket before it writes a byte. On Windows the service is the
// DefenseClawGateway SCM process, which is not this test; on Linux and macOS
// the service account the runtime descriptor names, which is not this test's
// account either.
func TestManagedCLIGatewayClientSendsNoTokenToAnUnverifiedListener(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("root is a trusted managed socket owner")
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)

	previousSecureClient, previousWindowsManaged, previousDeployment := secureClientHost, managedHostWindowsStandalone, managedStandaloneAdminDeployment
	t.Cleanup(func() {
		secureClientHost, managedHostWindowsStandalone, managedStandaloneAdminDeployment = previousSecureClient, previousWindowsManaged, previousDeployment
	})
	secureClientHost = func() bool { return false }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if runtime.GOOS == "windows" {
		managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	}
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: os.Geteuid() + 1}, nil
	}
	c := config.DefaultConfig()
	c.DeploymentMode = managed.DeploymentModeManagedEnterprise
	c.Enterprise.Profile = managed.ProfileStandalone

	client, err := gatewayPeerClient(c, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort(host, rawPort)+"/v1/skill/scan", strings.NewReader(`{"target":"/private/skill"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer managed-admin-token")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("an unverified listener answered HTTP %d", resp.StatusCode)
	}
	if received.Load() != 0 {
		t.Fatalf("an unverified listener received %d requests with the administrator's bearer", received.Load())
	}
}
