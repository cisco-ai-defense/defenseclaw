// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixturefs

import "testing"

func TestUnreadNestedPanicRestoresScope(t *testing.T) {
	func() {
		defer func() {
			if recover() != "inner panic" {
				t.Error("inner panic did not reach caller")
			}
			if Unreadable() {
				t.Error("scope remained unreadable after panic")
			}
		}()
		Unread(func() {
			Unread(func() {
				if !Unreadable() {
					t.Error("nested scope is readable")
				}
				panic("inner panic")
			})
		})
	}()
	Unread(func() {
		if !Unreadable() {
			t.Error("new scope is readable")
		}
	})
	if Unreadable() {
		t.Error("scope remained unreadable after return")
	}
}
