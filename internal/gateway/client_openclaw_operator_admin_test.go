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

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// connectors.openclaw.operator_admin false: admin RPCs are never sent and
// return the typed degrade error (rel-1-0-10 OC design 3.4).
func TestOpenClawOperatorAdminOffRefusesAdminRPCsLocally(t *testing.T) {
	c := &Client{pending: map[string]chan *ResponseFrame{}}
	if !c.RequestsOperatorAdmin() {
		t.Fatal("operator.admin must be requested by default")
	}
	c.SetOperatorAdmin(false)
	for _, call := range []func() error{
		func() error { return c.DisableSkill(context.Background(), "s") },
		func() error { return c.BlockMCPServer(context.Background(), "m") },
		func() error { return c.PatchConfig(context.Background(), "a.b", true) },
	} {
		// c.conn is nil: reaching the wire would fail with another error.
		if err := call(); !errors.Is(err, ErrOpenClawRemediationUnavailable) {
			t.Fatalf("err = %v, want ErrOpenClawRemediationUnavailable", err)
		}
	}
}

func TestOpenClawScopeUpgradeHintNamesTheOptOut(t *testing.T) {
	c := rejectionClient(t, t.TempDir())
	scope := errors.New("connect rejected: pairing required: device requests more scopes than approved (NOT_PAIRED)")
	if hint := c.handleConnectRejection(scope); !strings.Contains(hint, "operator_admin: false") {
		t.Fatalf("hint %q does not name the operator_admin opt-out", hint)
	}
	c.SetOperatorAdmin(false)
	if hint := c.handleConnectRejection(scope); strings.Contains(hint, "operator_admin") {
		t.Fatalf("hint %q names the opt-out although it is already set", hint)
	}
}
