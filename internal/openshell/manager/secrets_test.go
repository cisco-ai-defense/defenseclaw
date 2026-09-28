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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// TestStartRefusesSecretsTheMasksLeaveVisible pins that a mounted sandbox
// does not start again while its project holds a file the secret scan
// would mask now but its create-time masks leave visible, and starts once
// it is gone; a file inside a masked folder is hidden already.
func TestStartRefusesSecretsTheMasksLeaveVisible(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Workdir.Masks = []string{"config/prod.yaml"} })
	ctx := context.Background()
	e.ws.masked = []workspace.MaskedPath{{Rel: ".env", Reason: "name"}, {Rel: ".aws", Dir: true, Reason: "name"}}
	sb := e.create(sandboxapi.CreateRequest{Name: "maskbox"})
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	e.ws.scanned = []workspace.MaskedPath{{Rel: ".env"}, {Rel: ".aws/credentials"}, {Rel: "deploy/id_rsa", Reason: "name"}}
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	_, err := e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if !strings.Contains(apiErr.Message, "deploy/id_rsa") || strings.Contains(apiErr.Message, ".aws") {
		t.Fatalf("refusal = %q, want the one visible file named", apiErr.Message)
	}
	if n := e.fake.Calls(openshelltest.MethodStartSandbox); n != starts {
		t.Fatal("the sandbox started with the secret visible")
	}
	if got := e.ws.lastScan; got.Project != e.project || !slices.Contains(got.Masks, "config/prod.yaml") {
		t.Fatalf("scan options = %+v, want the policy's masks", got)
	}

	e.ws.scanned = []workspace.MaskedPath{{Rel: ".env"}}
	if _, err := e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatalf("start without new secrets: %v", err)
	}
}

// TestStartFailsClosedWhenTheSecretScanCannotFinish pins that a rescan that
// cannot check the whole project refuses the start, as it refuses a create.
func TestStartFailsClosedWhenTheSecretScanCannotFinish(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	sb := e.create(sandboxapi.CreateRequest{Name: "scanfail"})
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	e.ws.scanErr = errors.Join(workspace.ErrScanIncomplete, errors.New("too many entries"))
	_, err := e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
}
