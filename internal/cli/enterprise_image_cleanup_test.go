// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Both CLI formats must keep every per-image warning and its administrator
// command, including recorded tags when Docker could not list images.
func TestEnterpriseUninstallRendersEveryLeftoverSandboxImage(t *testing.T) {
	tags := []string{"defenseclaw/sandbox:sample-one", "defenseclaw/sandbox:sample-two"}
	for _, tc := range []struct {
		name    string
		warning func(string) string
		marker  string
	}{
		{"removal failed", func(tag string) string {
			return "left DefenseClaw sandbox image " + tag +
				" (a1b2c3d4e5f6) of user sample-user: image is being used by a container; as root run `docker image rm " + tag + "`"
		}, "being used"},
		{"Docker unavailable", func(tag string) string {
			return "left recorded DefenseClaw sandbox image " + tag +
				" of user sample-user: Docker CLI is missing; this image was not verified because Docker could not list it; as root check `docker image ls --filter label=io.defenseclaw.owner=aaaaaaaaaaaaaaaa`, then run `docker image rm " + tag + "`"
		}, "not verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := enterprisestatus.New("uninstall", "standalone", "linux", "1.0.2")
			for _, tag := range tags {
				r.AddWarning("sandbox_user_state", tc.warning(tag))
			}
			r.Finish("linux", 0)
			for _, asJSON := range []bool{false, true} {
				var out bytes.Buffer
				if err := printLifecycleResult(&out, r, asJSON); err != nil {
					t.Fatal(err)
				}
				for _, tag := range tags {
					if strings.Count(out.String(), tag) != 2 || !strings.Contains(out.String(), "docker image rm "+tag) {
						t.Errorf("json=%v output lost the warning or command for %s: %s", asJSON, tag, out.String())
					}
				}
				if !strings.Contains(out.String(), tc.marker) {
					t.Errorf("json=%v output lost %q: %s", asJSON, tc.marker, out.String())
				}
				if !asJSON && !strings.Contains(out.String(), "done with 2 warnings") {
					t.Errorf("text output did not count both warnings: %s", out.String())
				}
			}
		})
	}
}
