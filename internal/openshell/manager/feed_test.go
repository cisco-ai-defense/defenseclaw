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
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestFeedRingBuffer(t *testing.T) {
	f := NewFeed(4, nil)
	for i := 1; i <= 6; i++ {
		f.Publish(sandboxapi.ActivityEvent{Kind: "k", Sandbox: fmt.Sprintf("s%d", i%2), Message: fmt.Sprint(i)})
	}
	all := f.Since(0, "")
	if len(all) != 4 || all[0].Seq != 3 || all[3].Seq != 6 {
		t.Fatalf("buffer = %+v", all)
	}
	if got := f.Since(4, ""); len(got) != 2 || got[0].Seq != 5 {
		t.Fatalf("since 4 = %+v", got)
	}
	if got := f.Since(0, "s1"); len(got) != 2 || got[0].Seq != 3 || got[1].Seq != 5 {
		t.Fatalf("filtered = %+v", got)
	}
	if f.Seq() != 6 || all[0].Time.IsZero() {
		t.Fatalf("seq %d time %v", f.Seq(), all[0].Time)
	}
}

func TestFeedSubscribe(t *testing.T) {
	f := NewFeed(16, nil)
	f.Publish(sandboxapi.ActivityEvent{Kind: "old", Sandbox: "a"})
	backlog, ch, cancel, ok := f.Subscribe(0, "a")
	if !ok || len(backlog) != 1 || backlog[0].Kind != "old" {
		t.Fatalf("backlog = %+v", backlog)
	}
	f.Publish(sandboxapi.ActivityEvent{Kind: "other", Sandbox: "b"})
	f.Publish(sandboxapi.ActivityEvent{Kind: "new", Sandbox: "a"})
	select {
	case ev := <-ch:
		if ev.Kind != "new" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	cancel()
	cancel()
	if _, open := <-ch; open {
		t.Fatal("channel open after cancel")
	}
}

func TestFeedSlowSubscriberGetsDropMarker(t *testing.T) {
	f := NewFeed(1024, nil)
	_, ch, cancel, _ := f.Subscribe(0, "")
	defer cancel()
	for i := 0; i < defaultSubscriberBuf+10; i++ {
		f.Publish(sandboxapi.ActivityEvent{Kind: "k"})
	}
	for i := 0; i < defaultSubscriberBuf; i++ {
		<-ch
	}
	f.Publish(sandboxapi.ActivityEvent{Kind: "after"})
	marker := <-ch
	if marker.Kind != sandboxapi.ActivityDropped || marker.BytesUp != 10 {
		t.Fatalf("marker = %+v", marker)
	}
	if ev := <-ch; ev.Kind != "after" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestFeedSubscriberLimit(t *testing.T) {
	f := NewFeed(4, nil)
	var cancels []func()
	for i := 0; i < maxSubscribers; i++ {
		_, _, cancel, ok := f.Subscribe(0, "")
		if !ok {
			t.Fatalf("subscriber %d refused", i)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, _, ok := f.Subscribe(0, ""); ok {
		t.Fatal("subscriber over the limit accepted")
	}
	cancels[0]()
	if _, _, _, ok := f.Subscribe(0, ""); !ok {
		t.Fatal("slot not released")
	}
}
