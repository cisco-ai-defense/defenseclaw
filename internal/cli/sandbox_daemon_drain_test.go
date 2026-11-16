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

//go:build unix

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// syncBuffer is a buffer one goroutine writes and another reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTheDrainHoldsTheAccountsStartsUntilTheLifecycleIsDone: the managed
// lifecycle read the account's status, then stopped its daemon and
// gateway; a sandbox started and ended in between was stopped with the
// gateway, its MicroVM with no flush. The drain the lifecycle now runs as
// the account takes the lifecycle lock first, so no create or start of
// the account's DefenseClaw gets through (openshell.LockSandboxStart is
// refused), checks under it, says so, and holds the lock until the
// lifecycle closes its input, after its stops. A check that refuses holds
// nothing and says nothing.
func TestTheDrainHoldsTheAccountsStartsUntilTheLifecycleIsDone(t *testing.T) {
	dir := t.TempDir()
	lock := func(ctx context.Context) (func(), error) { return openshell.LockGatewayLifecycle(ctx, dir) }
	checks := 0
	in, done := io.Pipe()
	var out syncBuffer
	exited := make(chan error, 1)
	go func() {
		exited <- drainAccountGateway(context.Background(), in, &out, sandboxDrain{lock: lock, hold: time.Minute,
			check: func(context.Context) error {
				checks++
				// Under the lock: a start is refused already.
				if _, err := openshell.LockSandboxStart(dir); !errors.Is(err, openshell.ErrGatewayBusy) {
					t.Errorf("a start during the check: %v", err)
				}
				return nil
			}})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), openshell.LifecycleDrained) {
		if time.Now().After(deadline) {
			t.Fatalf("the drain never said it held the gateway: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The lifecycle stops the units now: a start is still refused.
	if _, err := openshell.LockSandboxStart(dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a start while the lifecycle stops the units: %v", err)
	}
	_ = done.Close()
	if err := <-exited; err != nil || checks != 1 {
		t.Fatalf("drain = %v (checks %d)", err, checks)
	}
	unlock, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatalf("a start after the drain: %v", err)
	}
	unlock()

	// Something runs: the drain refuses, says nothing, and holds nothing.
	out = syncBuffer{}
	refusal := errors.New("1 MicroVM run as this account")
	err = drainAccountGateway(context.Background(), strings.NewReader(""), &out, sandboxDrain{lock: lock, hold: time.Minute,
		check: func(context.Context) error { return refusal }})
	if !errors.Is(err, refusal) || out.String() != "" {
		t.Fatalf("a refused drain = %v, said %q", err, out.String())
	}
	unlock, err = openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatalf("a start after a refused drain: %v", err)
	}
	unlock()

	// A lifecycle that never says it is done: the hold ends with an error.
	held, _ := io.Pipe()
	err = drainAccountGateway(context.Background(), held, &syncBuffer{}, sandboxDrain{lock: lock, hold: 50 * time.Millisecond,
		check: func(context.Context) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "never said its stop was done") {
		t.Fatalf("a drain held past its bound = %v", err)
	}
}
