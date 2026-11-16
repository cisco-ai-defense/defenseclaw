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
	"errors"
	"testing"
)

// GAP-0592: an OpenClaw pairing rejection reaches /health with the operator
// step while the client keeps retrying; any other failure keeps the plain
// reconnecting state.
func TestPublishGatewayConnectErrorPutsTheOperatorStepInHealth(t *testing.T) {
	s := &Sidecar{health: NewSidecarHealth()}
	s.health.SetGateway(StateReconnecting, "", nil)

	s.publishGatewayConnectError(errors.New("connection refused"), "")
	if got := s.health.Snapshot().Gateway; got.LastError != "" || got.Details != nil {
		t.Fatalf("plain failure changed gateway health: %+v", got)
	}

	rejection := errors.New("gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)")
	hint := openClawPairingApprovalHint("abc")
	s.publishGatewayConnectError(rejection, hint)
	got := s.health.Snapshot().Gateway
	if got.State != StateReconnecting || got.LastError != rejection.Error() {
		t.Fatalf("gateway health = %+v, want reconnecting with the rejection", got)
	}
	if got.Details["hint"] != hint || got.Details["reason"] != "openclaw_operator_action_required" {
		t.Fatalf("gateway details = %v, want the operator step", got.Details)
	}
}
