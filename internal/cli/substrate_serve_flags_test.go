// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0042: in a cluster only the actor listener may be plain HTTP.
func TestServeRefusesPlainHTTPInACluster(t *testing.T) {
	old := serveFlags
	t.Cleanup(func() { serveFlags = old })
	serveFlags.substrate, serveFlags.plainHTTP = true, true
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	err := runServe(serveCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--actor-plain-http") {
		t.Fatalf("plain HTTP in a cluster: %v", err)
	}
}

// STEER 11-12 22:55Z: an OSS cluster without OIDC signs people in with
// their Kubernetes credentials; OIDC, a managed install or the flag turn
// it off.
func TestKubeSignInOnlyForOSSWithoutOIDC(t *testing.T) {
	old := serveFlags
	t.Cleanup(func() { serveFlags = old })
	oss := &config.Config{}
	if !substrateKubeSignIn(oss) {
		t.Fatal("OSS without OIDC: no Kubernetes sign-in")
	}
	withOIDC := &config.Config{}
	withOIDC.Substrate.Identity.OIDC.Issuer = "https://idp.example"
	if substrateKubeSignIn(withOIDC) {
		t.Fatal("Kubernetes sign-in next to an OIDC issuer")
	}
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if substrateKubeSignIn(managedCfg) {
		t.Fatal("a managed install accepts Kubernetes sign-in")
	}
	serveFlags.noKubeSignIn = true
	if substrateKubeSignIn(oss) {
		t.Fatal("--no-kube-sign-in ignored")
	}
}
