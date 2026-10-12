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

// A create carries the managed daemon's driver choice; a gateway on another
// driver refuses it (a running sandbox never switches driver).
func TestDriverChoiceContext(t *testing.T) {
	if _, ok := driverChoiceFrom(context.Background()); ok {
		t.Fatal("a choice without one")
	}
	want := openshell.DriverChoice{Driver: openshell.DriverDocker, Reason: openshell.DriverReasonKVMMissing}
	got, ok := driverChoiceFrom(WithDriverChoice(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("choice %+v %t", got, ok)
	}
	err := driverChoiceMismatch(want, openshell.DriverVM)
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeConflict || apiErr.Detail != DriverMismatchDetail ||
		!strings.Contains(apiErr.Message, "docker (fallback: KVM not available on this computer) driver") ||
		!strings.Contains(apiErr.Message, "runs the vm driver") {
		t.Fatalf("mismatch: %v", err)
	}
}
