// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tetragon

import (
	"os"
	"testing"
)

func TestDialRefusesWritableInfoDirectory(t *testing.T) {
	fake := newFakeTetragon(t, "v1.7.1")
	if err := os.Chmod(fake.dir, 0o770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(fake.dir, 0o750)
	_, err := fake.dial(t, ScopeConsume, myTrust())
	wantReason(t, err, ReasonUntrusted)
}
