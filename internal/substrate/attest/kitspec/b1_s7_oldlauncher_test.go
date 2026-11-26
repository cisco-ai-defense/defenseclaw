// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// This test renders the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package kitspec

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// B1 S7: a launcher older than 1.0.11 writes no registry files at agent
// start. A template built now must still carry the build-time placeholder
// line of each registry bound in substrate.secrets, or that launcher's
// agents get a 401 from a private npm registry. Build-time path: remove in 1.0.12, when launchers older than 1.0.11 are unsupported.
func TestB1S7OldLauncherNewTemplateKeepsBuildTimeRegistryLines(t *testing.T) {
	secrets := []config.SubstrateSecret{{Name: "npm-corp", Source: "ate-secret://k8s.io/p/ns/npm/token",
		Inject: config.SubstrateSecretInject{Hosts: []string{"npm.corp.example"}, Header: "Authorization", Prefix: "Bearer ", Placeholder: "DC_SECRET_NPM"}}}
	spec, _, err := Spec(Options{Connector: "antigravity", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r"),
		RegistryTokens: kit.NPMRegistryTokens(secrets)})
	if err != nil {
		t.Fatal(err)
	}
	rc, found := "", false
	for _, f := range spec.Files {
		if f.Path == kit.NPMGlobalConfig {
			rc, found = string(f.Data), true
		}
	}
	if !found || !strings.Contains(rc, "//npm.corp.example/:_authToken=DC_SECRET_NPM\n") || strings.Count(rc, "_authToken=") != 1 {
		t.Fatalf("the template's %s (found %v) must name the bound registry for old launchers:\n%s", kit.NPMGlobalConfig, found, rc)
	}
}
