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
)

func TestPerUserGatewayClientDoesNotTrustManagedModeFromEnvironment(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	previousFactory := perUserGatewayClientFactory
	previousSecureClient := hookcli.SecureClientHost
	previousWindowsManaged := hookcli.ManagedHostWindowsStandalone
	t.Cleanup(func() {
		perUserGatewayClientFactory = previousFactory
		hookcli.SecureClientHost = previousSecureClient
		hookcli.ManagedHostWindowsStandalone = previousWindowsManaged
	})
	hookcli.SecureClientHost = func() bool { return false }
	hookcli.ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
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

func TestManagedGatewayClientKeepsServiceAccountTransportDuringUpgrade(t *testing.T) {
	previousFactory := perUserGatewayClientFactory
	previousManagedFactory := managedGatewayClientFactory
	previousSecureClient := hookcli.SecureClientHost
	previousWindowsManaged := hookcli.ManagedHostWindowsStandalone
	t.Cleanup(func() {
		perUserGatewayClientFactory = previousFactory
		managedGatewayClientFactory = previousManagedFactory
		hookcli.SecureClientHost = previousSecureClient
		hookcli.ManagedHostWindowsStandalone = previousWindowsManaged
	})
	hookcli.SecureClientHost = func() bool { return false }
	hookcli.ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		t.Fatal("managed service account was required to match the CLI account")
		return nil, nil
	}
	called := false
	managedGatewayClientFactory = func(_ time.Duration, addr, service string) (*http.Client, error) {
		called = true
		if addr != "127.0.0.1:18970" || service != hookcli.ManagedServiceName(false) {
			t.Errorf("managed service peer = %q/%q", addr, service)
		}
		return nil, errors.New("connected managed gateway peer is unverified")
	}
	c := config.DefaultConfig()
	c.DeploymentMode = managed.DeploymentModeManagedEnterprise
	client, err := gatewayPeerClient(c, "127.0.0.1", 18970, time.Second)
	if !called || client != nil || err == nil {
		t.Fatalf("managed gateway bypassed service peer check: called=%t client=%v error=%v", called, client, err)
	}
}

func TestSecureClientGatewayClientRequiresVerifiedServiceTransport(t *testing.T) {
	previousFactory := managedGatewayClientFactory
	previousSecureClient := hookcli.SecureClientHost
	t.Cleanup(func() {
		managedGatewayClientFactory = previousFactory
		hookcli.SecureClientHost = previousSecureClient
	})
	hookcli.SecureClientHost = func() bool { return true }
	called := false
	managedGatewayClientFactory = func(_ time.Duration, addr, service string) (*http.Client, error) {
		called = true
		if addr != "127.0.0.1:18970" || service != hookcli.ManagedServiceName(true) {
			t.Errorf("service peer = %q/%q", addr, service)
		}
		return nil, errors.New("connected managed gateway peer is unverified")
	}
	c := config.DefaultConfig()
	c.DeploymentMode = managed.DeploymentModeManagedEnterprise
	c.Enterprise.Profile = managed.ProfileSecureClient
	client, err := gatewayPeerClient(c, "127.0.0.1", 18970, time.Second)
	if !called || client != nil || err == nil {
		t.Fatalf("Secure Client bypassed service peer check: called=%t client=%v error=%v", called, client, err)
	}
}
