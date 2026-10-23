// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestPerUserGatewayClientDoesNotTrustManagedModeFromEnvironment(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	previousFactory := perUserGatewayClientFactory
	previousSecureClient := secureClientHost
	previousWindowsManaged := managedHostWindowsStandalone
	t.Cleanup(func() {
		perUserGatewayClientFactory = previousFactory
		secureClientHost = previousSecureClient
		managedHostWindowsStandalone = previousWindowsManaged
	})
	secureClientHost = func() bool { return false }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	called := false
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		called = true
		return nil, errors.New("connected peer was rejected")
	}
	_, err := gatewayPeerClient(config.DefaultConfig(), "127.0.0.1", 18970, time.Second)
	if !called || err == nil || err.Error() != "connected peer was rejected" {
		t.Fatalf("managed environment bypassed per-user socket proof: called=%t error=%v", called, err)
	}
}
