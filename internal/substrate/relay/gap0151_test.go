// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"strings"
	"testing"
)

// GAP-0151: the E9 warning of an open-source agent that signs in travels in
// the hello (and the status), so the launcher can show it where a
// full-screen agent cannot erase it; other agents have none.
func TestHelloCarriesTheSigninWarning(t *testing.T) {
	ag := signinServer("antigravity", false, nil)
	if err := ag.init(); err != nil {
		t.Fatal(err)
	}
	if w := ag.hello("", nil).Warning; !strings.Contains(w, "snapshot") {
		t.Fatalf("hello warning %q, want the snapshot warning", w)
	}
	b := EncodeControl(ag.hello("", nil))
	_, p, _ := Decode(b)
	if c, err := DecodeControl(p); err != nil || c.Warning != ag.agent.Banner {
		t.Fatalf("decoded hello %+v %v", c, err)
	}
	cc := signinServer("claudecode", false, nil)
	if err := cc.init(); err != nil {
		t.Fatal(err)
	}
	if w := cc.hello("", nil).Warning; w != "" {
		t.Fatalf("claudecode hello warning %q, want none", w)
	}
}
