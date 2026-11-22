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

package chainstate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// syncBuffer is a Warn writer safe for the service's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestForkLinkHoldsTheChildsFirstCalls is GAP-0091 (race): while the
// parent's windows are being copied into a new child store, a concurrent
// egress check of the child waits for the copy and sees the parent's
// secret read, instead of an empty window.
func TestForkLinkHoldsTheChildsFirstCalls(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := newHarness(t, t.TempDir(), Options{ParentOf: func(_ context.Context, _, uid string) (string, error) {
		if uid != actorB.UID {
			return "", nil
		}
		once.Do(func() { close(entered) })
		<-release
		return actorA.UID, nil
	}})
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)

	first := make(chan error, 1)
	go func() {
		_, err := h.client.CheckEgress(context.Background(), EgressRequest{Actor: actorB, Host: "example.com", Method: "GET"})
		first <- err
	}()
	<-entered
	second := make(chan EgressVerdict, 1)
	go func() {
		v, _ := h.client.CheckEgress(context.Background(), EgressRequest{Actor: actorB, Host: "example.com", Method: "POST"})
		second <- v
	}()
	select {
	case v := <-second:
		t.Fatalf("a concurrent egress check ran before the fork copy: %+v", v)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if v := <-second; !v.Deny {
		t.Fatalf("child egress after the parent's secret read: %+v", v)
	}
}

// TestForkLinkFailureIsNotSilent is GAP-0091: a failed link is not a
// child without windows. The call answers unavailable (the caller's fail
// mode applies), the failure is reported, and the next call links.
func TestForkLinkFailureIsNotSilent(t *testing.T) {
	var calls atomic.Int32
	warn := &syncBuffer{}
	h := newHarness(t, t.TempDir(), Options{Warn: warn, ParentOf: func(_ context.Context, _, uid string) (string, error) {
		if uid != actorB.UID {
			return "", nil
		}
		if calls.Add(1) == 1 {
			return "", errors.New("registrations unavailable")
		}
		return actorA.UID, nil
	}})
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	// No client retry: the first answer is the failure itself.
	_, err := h.svc.Egress(context.Background(), EgressRequest{Actor: actorB, Host: "example.com", Method: "POST"})
	if err == nil || !strings.Contains(warn.String(), "fork link for") {
		t.Fatalf("failed link: err=%v warn=%q", err, warn.String())
	}
	v, err := h.client.CheckEgress(context.Background(), EgressRequest{Actor: actorB, Host: "example.com", Method: "POST"})
	if err != nil || !v.Deny || calls.Load() != 2 {
		t.Fatalf("retried link: %+v err=%v calls=%d", v, err, calls.Load())
	}
}
