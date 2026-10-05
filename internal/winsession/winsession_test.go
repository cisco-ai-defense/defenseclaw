// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winsession

import "testing"

func TestNotifyLogonCoalescesWithoutBlocking(t *testing.T) {
	for i := 0; i < 5; i++ {
		NotifyLogon()
	}
	select {
	case <-Logons():
	default:
		t.Fatal("a notification must be pending")
	}
	select {
	case <-Logons():
		t.Fatal("a burst must coalesce into one pending signal")
	default:
	}
}
