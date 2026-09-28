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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// With openshell.admin.allow_unblock false, every unblock refusal cited
// allow_unblock: for a host on the organization's block list (which no
// setting of the user's opens), for a host that was not blocked at all,
// and in a strict sandbox, where approving its ask is the way on. Each gets
// its own answer now; a blocked host the organization would let the user
// unblock still names allow_unblock.
func TestUnblockRefusalsSayWhatApplies(t *testing.T) {
	off := false
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Admin.AllowUnblock = &off
		c.OpenShell.Admin.EgressBlock = []string{"example.com"}
	})
	e.run()
	open := e.create(sandboxapi.CreateRequest{Name: "openbox"})
	strict := e.create(sandboxapi.CreateRequest{Name: "strictbox", Pack: "strict", Project: e.otherProject("strict")})
	ctx := context.Background()
	unblock := func(req sandboxapi.UnblockRequest) *sandboxapi.Error {
		t.Helper()
		_, err := e.m.Unblock(ctx, req)
		if err == nil {
			t.Fatalf("unblock %+v was accepted", req)
		}
		var apiErr *sandboxapi.Error
		if !errors.As(err, &apiErr) {
			t.Fatalf("unblock %+v: %v", req, err)
		}
		return apiErr
	}

	got := unblock(sandboxapi.UnblockRequest{Host: "example.com", Sandbox: open.Name})
	if got.Violation == nil || got.Violation.Constraint != "openshell.admin.egress_block" || !strings.Contains(got.Detail, "blocklist") {
		t.Fatalf("admin-blocked host = %+v", got)
	}
	got = unblock(sandboxapi.UnblockRequest{Host: "www.example.com", Always: true})
	if got.Code != sandboxapi.CodeInvalid || !strings.Contains(got.Message, "www.example.com is not blocked") {
		t.Fatalf("host that is not blocked = %+v", got)
	}
	got = unblock(sandboxapi.UnblockRequest{Host: "www.example.net", Sandbox: strict.Name})
	if got.Violation == nil || got.Violation.Constraint == "openshell.admin.allow_unblock" ||
		!strings.Contains(got.Violation.Detail, "defenseclaw sandbox approvals") {
		t.Fatalf("strict sandbox = %+v", got)
	}
	got = unblock(sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: open.Name})
	if got.Violation == nil || got.Violation.Constraint != "openshell.admin.allow_unblock" {
		t.Fatalf("blocklisted host with unblocks off = %+v", got)
	}
}
