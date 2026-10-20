// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// An offline signer judges a platform-only key by the --platform targets,
// not by the operating system it runs on (GAP-0005): a Linux or Windows
// workstation signs a macOS bundle that sets enterprise.openshell.e2fsprogs_dir,
// and every signer refuses it for a Linux or Windows target. A device keeps
// judging the key by its own platform.
func TestComposeJudgesPlatformKeysByTarget(t *testing.T) {
	config := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n"+
		"  openshell:\n    install: prerequisite\n    driver: vm\n    version: \"0.1.3\"\n    gateway_port: 17670\n"+
		"    e2fsprogs_dir: /opt/cisco/defenseclaw-deps/e2fsprogs/sbin\n", 1)
	for _, tc := range []struct {
		name    string
		targets []string
		refuse  bool
	}{
		{"darwin", []string{enterprisebundle.PlatformDarwin}, false},
		{"linux", []string{enterprisebundle.PlatformLinux}, true},
		{"windows", []string{enterprisebundle.PlatformWindows}, true},
		{"darwin and linux", []string{enterprisebundle.PlatformDarwin, enterprisebundle.PlatformLinux}, true},
		{"linux and darwin", []string{enterprisebundle.PlatformLinux, enterprisebundle.PlatformDarwin}, true},
	} {
		for _, signer := range enterprisebundle.Platforms {
			t.Run(tc.name+"/signed-on-"+signer, func(t *testing.T) {
				root, b := writeBundle(t, config)
				in := enterprisebundle.ComposeInput{
					Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
					Platforms: tc.targets, CreatedAt: signedAt, CreatedBy: "operator:alice",
					ProductVersion: "1.0.2", HostPlatform: signer, Digester: digester,
				}
				_, _, err := enterprisebundle.Compose(context.Background(), in)
				if !tc.refuse {
					if err != nil {
						t.Fatalf("sign for %v: %v", tc.targets, err)
					}
					return
				}
				if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(err.Error(), "e2fsprogs_dir applies to macOS only") {
					t.Fatalf("sign for %v: got %v, want config_invalid naming e2fsprogs_dir", tc.targets, err)
				}
			})
		}
	}

	f := newFixture(t, config, func(in *enterprisebundle.ComposeInput) {
		in.Platforms = []string{enterprisebundle.PlatformDarwin}
	})
	in := f.input(t, f.bundle, anchors(t, "acme", []string{"eng"}, 0, activeKey("k1", f.key.Public())))
	in.Platform = enterprisebundle.PlatformDarwin
	if _, err := enterprisebundle.Verify(context.Background(), in); err != nil {
		t.Fatalf("verify on darwin: %v", err)
	}
	root, b := writeBundle(t, config)
	if _, _, err := enterprisebundle.LoadConfigForPlatform(b, root, enterprisebundle.PlatformLinux); !strings.Contains(errString(err), "e2fsprogs_dir applies to macOS only") {
		t.Fatalf("device load on linux: got %v, want e2fsprogs_dir refused", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
