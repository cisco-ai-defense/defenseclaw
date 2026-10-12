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

//go:build !windows

package sandboxcli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0451: on a managed computer a sandbox service that does not answer
// is the organization's to fix; no per-user gateway command is offered.
func TestManagedDaemonDownNamesNoGatewayCommand(t *testing.T) {
	down := &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: "dial"}
	if err := apiError(down); !strings.Contains(err.Error(), "defenseclaw-gateway start") {
		t.Fatalf("unmanaged: %v", err)
	}
	withManagedHost(t)
	err := apiError(down)
	if strings.Contains(err.Error(), "defenseclaw-gateway") || !strings.Contains(err.Error(), "your sandbox service does not answer") {
		t.Fatalf("managed: %v", err)
	}
	if got := apiError(errors.New("other")); got.Error() != "other" {
		t.Fatalf("other errors pass through: %v", got)
	}
}
