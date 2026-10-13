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

package sandboxreg

import (
	"errors"
	"testing"
)

// A sandbox never switches driver: a bind that reports another driver than
// the registration was resolved for is refused, and the reason is kept.
func TestStoreBindKeepsTheResolvedDriver(t *testing.T) {
	s, _, _ := newTestStore(t)
	r := pending(t)
	r.Driver, r.DriverReason = "docker", "kvm_missing"
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	wrong := bind(1)
	wrong.Driver = "vm"
	if _, err := s.Bind(1001, r.ID, wrong); !errors.Is(err, ErrDriverMismatch) {
		t.Fatalf("bind on another driver: %v", err)
	}
	bad := bind(1)
	bad.Driver = "podman"
	if _, err := s.Bind(1001, r.ID, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bind with an unknown driver: %v", err)
	}
	ok := bind(1)
	ok.Driver = "docker"
	live, err := s.Bind(1001, r.ID, ok)
	if err != nil || live.Driver != "docker" || live.DriverReason != "kvm_missing" {
		t.Fatalf("bind: %+v %v", live, err)
	}
}
