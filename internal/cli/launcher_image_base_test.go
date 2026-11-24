// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-10:GAP-2064: on a managed computer `sandbox run` builds the
// harness image in the account's daemon, on the organization's
// openshell.image.base and harness_versions, while `sandbox image build`
// (also --force) builds it in the launcher from a configuration that had
// neither, so it kept the previous base tag. The launcher takes both from
// the daemon's status, as it takes the ports and the gateway.
func TestGAP2064LauncherBuildsImagesOnTheDaemonsBase(t *testing.T) {
	const base = "local/openshell-base@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	status := &sandboxapi.Status{Enabled: true, ImageBase: base, HarnessVersions: map[string]string{"codex": "0.1.2"}}
	cfg := launcherManagedConfig(config.DefaultConfig(), status)
	if cfg.OpenShell.Image.Base != base || cfg.OpenShell.Image.HarnessVersions["codex"] != "0.1.2" {
		t.Fatalf("launcher image base %q, harness versions %v; want the daemon's %q, codex 0.1.2", cfg.OpenShell.Image.Base, cfg.OpenShell.Image.HarnessVersions, base)
	}
	// A daemon that names none leaves the launcher's own.
	own := config.DefaultConfig()
	own.OpenShell.Image.Base = "mine"
	if got := launcherManagedConfig(own, &sandboxapi.Status{Enabled: true}).OpenShell.Image.Base; got != "mine" {
		t.Fatalf("an empty daemon base replaced the launcher's: %q", got)
	}
}
