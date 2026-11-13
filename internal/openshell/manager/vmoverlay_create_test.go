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

package manager

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0007 (macOS) and GAP-0570 (Linux): a create on the vm driver first
// makes the driver's overlay template root-owned, for the gateway's
// release; when that fails the create is refused before anything is made,
// and a docker create never asks for it.
func TestCreateOnVMPreparesTheOverlayTemplateFirst(t *testing.T) {
	var releases []string
	fail := error(nil)
	template := func(_ context.Context, release string) error {
		releases = append(releases, release)
		return fail
	}

	e := newVMEnv(t, nil)
	e.m.opts.VMOverlayTemplate = template
	e.create(sandboxapi.CreateRequest{Name: "vm-template", Copy: true})
	if len(releases) != 1 || releases[0] != e.gw.Version {
		t.Fatalf("template prepared for %q, want once for the gateway's release %q", releases, e.gw.Version)
	}

	fail = errors.Join(openshell.ErrVMOverlayTemplate, errors.New("no folder holds e2fsprogs' mke2fs and debugfs"))
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-no-template", Copy: true, Project: e.otherProject("other")})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), "root-owned root folder") ||
		!strings.Contains(err.Error(), "nothing was created") {
		t.Fatalf("create without a template = %v", err)
	}
	if _, err := e.m.Get(t.Context(), "vm-no-template"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("the refused create left a sandbox: %v", err)
	}

	releases = nil
	d := newEnv(t, nil)
	d.m.opts.VMOverlayTemplate = template
	d.create(sandboxapi.CreateRequest{Name: "dk-template"})
	if len(releases) != 0 {
		t.Fatalf("a docker create prepared a MicroVM template (%q)", releases)
	}
}

// GatewayVMOverlayTemplate leaves a release whose template layout
// DefenseClaw does not know to the driver: it asks for no e2fsprogs.
func TestGatewayVMOverlayTemplateSkipsAnUnknownLayout(t *testing.T) {
	asked := false
	tools := func() (string, error) { asked = true; return "", errors.New("unexpected") }
	for _, release := range []string{"", "0.1.4", "0.2.0", "not a version"} {
		if err := GatewayVMOverlayTemplate(t.TempDir(), tools)(t.Context(), release); err != nil || asked {
			t.Fatalf("release %q: %v (tools asked: %v)", release, err, asked)
		}
	}
}
