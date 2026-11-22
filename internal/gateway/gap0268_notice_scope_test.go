// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"testing"
)

// substrate-1 GAP-0268: the security notice a refusal queues for the next
// model requests ([DEFENSECLAW SECURITY ENFORCEMENT]) was gateway-wide. On
// Agent Substrate one gateway serves many actors, so a refusal of actor A
// was injected into actor B's model requests (another agent, possibly
// another person) and told B's model about a request B never made. A
// notice now goes only to the requests of the actor it was raised for; a
// host gateway (one user) keeps one notice for every session.
func TestGAP0268RefusalNoticeReachesOnlyItsOwnActor(t *testing.T) {
	covAllowPrivate(t)
	covSetManaged(t, false)
	const notice = "[DEFENSECLAW SECURITY ENFORCEMENT]"
	for _, w := range f16Wires() {
		if w.name != "chat" && w.name != "responses" {
			continue // the passthrough injects the notice on the OpenAI wires
		}
		t.Run(w.name, func(t *testing.T) {
			rg := newF14Rig(t, w.provider, "action")
			rg.proxy.notify = NewNotificationQueue()
			a := f14Caller{actor: f14Actor(t, "gap0268-a", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d")}
			b := f14Caller{actor: f14Actor(t, "gap0268-b", "9a1f3c5e-2b7d-4e8f-a0c6-1d3b5f7e9a55")}
			if fwd, _ := rg.postF16(t, w, a, []f14Item{{"user", "please " + covMarker}}, false); fwd {
				t.Fatal("actor A's refused request was forwarded")
			}
			if fwd, _ := rg.postF16(t, w, b, []f14Item{{"user", "Say OK."}}, false); !fwd {
				t.Fatal("actor B's benign request was refused")
			}
			if body := rg.lastBody(); bytes.Contains(body, []byte(notice)) {
				t.Errorf("actor A's refusal notice reached actor B's model request: %.400s", body)
			}
			host := f14Caller{session: "gap0268-host", owner: true}
			if fwd, _ := rg.postF16(t, w, host, []f14Item{{"user", "Say OK."}}, false); !fwd {
				t.Fatal("the host request was refused")
			}
			if body := rg.lastBody(); bytes.Contains(body, []byte(notice)) {
				t.Errorf("actor A's refusal notice reached a host caller's model request: %.400s", body)
			}
			if fwd, _ := rg.postF16(t, w, a, []f14Item{{"user", "Say OK again."}}, false); !fwd {
				t.Fatal("actor A's next benign request was refused")
			}
			if body := rg.lastBody(); !bytes.Contains(body, []byte(notice)) {
				t.Errorf("actor A's own next model request does not carry its refusal notice: %.400s", body)
			}
		})
	}
}

// A host gateway serves one user: a notice raised by one session still
// reaches every session's next request, as before.
func TestGAP0268HostNoticeStillReachesEverySession(t *testing.T) {
	covAllowPrivate(t)
	covSetManaged(t, false)
	w := f16Wires()[0]
	rg := newF14Rig(t, w.provider, "action")
	rg.proxy.notify = NewNotificationQueue()
	if fwd, _ := rg.postF16(t, w, f14Caller{session: "gap0268-s1", owner: true}, []f14Item{{"user", "please " + covMarker}}, false); fwd {
		t.Fatal("the refused request was forwarded")
	}
	if fwd, _ := rg.postF16(t, w, f14Caller{session: "gap0268-s2", owner: true}, []f14Item{{"user", "Say OK."}}, false); !fwd {
		t.Fatal("the benign request was refused")
	}
	if body := rg.lastBody(); !bytes.Contains(body, []byte("[DEFENSECLAW SECURITY ENFORCEMENT]")) {
		t.Errorf("a host session's next request does not carry the notice: %.400s", body)
	}
}
