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

package mqtt

import (
	"bytes"
	"testing"

	"github.com/eclipse/paho.golang/paho"
)

// The client routes inbound PUBLISH packets through OnPublishReceived (the
// replacement of the deprecated NewSingleHandlerRouter): a matching filter
// gets the message, an unmatched topic reaches no handler and is reported
// not handled, so a later callback still sees AlreadyHandled=false.
func TestPahoClientOnPublishReceivedDispatchesToMatchingSubscription(t *testing.T) {
	c := NewPahoClient("mqtt://127.0.0.1:1883", "test")
	var got []Message
	c.subs["defenseclaw/+/+/+/heartbeat"] = func(m Message) { got = append(got, m) }
	c.subs["defenseclaw/1/1/7/verdict/req"] = func(Message) { t.Error("wrong handler called") }

	handled, err := c.onPublishReceived(paho.PublishReceived{Packet: &paho.Publish{
		Topic: "defenseclaw/1/1/7/heartbeat", Payload: []byte{1, 2}, QoS: 1,
	}})
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if len(got) != 1 || got[0].Topic != "defenseclaw/1/1/7/heartbeat" || !bytes.Equal(got[0].Payload, []byte{1, 2}) || got[0].QoS != 1 {
		t.Fatalf("dispatched %+v", got)
	}

	if handled, err := c.onPublishReceived(paho.PublishReceived{Packet: &paho.Publish{Topic: "other/topic"}}); err != nil || handled {
		t.Fatalf("unmatched topic: handled=%v err=%v", handled, err)
	}
	if handled, _ := c.onPublishReceived(paho.PublishReceived{}); handled {
		t.Fatal("a nil packet must not count as handled")
	}
	if len(got) != 1 {
		t.Fatalf("unmatched topic was dispatched: %+v", got)
	}
}
