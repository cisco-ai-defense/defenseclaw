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

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

const aiDiscoveryLifecycleTestTimeout = 5 * time.Second

func awaitAIDiscoverySignal(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(aiDiscoveryLifecycleTestTimeout):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func awaitAIDiscoveryResult(t *testing.T, ch <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(aiDiscoveryLifecycleTestTimeout):
		t.Fatalf("timed out waiting for %s", label)
		return nil
	}
}

func newGatewayLifecycleDiscovery(t *testing.T) *inventory.ContinuousDiscoveryService {
	t.Helper()
	homeDir := t.TempDir()
	return inventory.NewContinuousDiscoveryServiceWithOptions(inventory.AIDiscoveryOptions{
		DataDir:         t.TempDir(),
		HomeDir:         homeDir,
		ScanRoots:       []string{homeDir},
		ScanInterval:    time.Hour,
		ProcessInterval: time.Hour,
	}, nil)
}

func TestSidecarAIDiscoveryClaimPreventsActiveCloseButRetiresCoalescedService(t *testing.T) {
	first := newGatewayLifecycleDiscovery(t)
	second := newGatewayLifecycleDiscovery(t)
	third := newGatewayLifecycleDiscovery(t)
	sidecar := &Sidecar{aiDiscovery: first}

	claimedService, firstRun, ok := sidecar.claimAIDiscoveryRun()
	if !ok || claimedService != first || firstRun == nil {
		t.Fatal("sidecar did not atomically claim the active discovery service")
	}
	if old := sidecar.swapAIDiscovery(second); old != first {
		t.Fatalf("first swap returned %p, want %p", old, first)
	}
	if closed, err := first.CloseIfNeverStarted(); err != nil || closed {
		t.Fatalf("claimed first service close = (%v, %v), want (false, nil)", closed, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := firstRun(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("first service Run error = %v, want context.Canceled", err)
	}

	// Simulate a second reload arriving before the restart worker claims the
	// intermediate generation. The swap exposes third and the unclaimed second
	// generation can be closed immediately instead of leaking inventory.db.
	if old := sidecar.swapAIDiscovery(third); old != second {
		t.Fatalf("coalesced swap returned %p, want intermediate %p", old, second)
	}
	if closed, err := second.CloseIfNeverStarted(); err != nil || !closed {
		t.Fatalf("intermediate close = (%v, %v), want (true, nil)", closed, err)
	}
	if _, err := second.InventoryStore().SchemaVersion(); err == nil {
		t.Fatal("intermediate inventory store still accepted queries after retirement")
	}
	if closed, err := third.CloseIfNeverStarted(); err != nil || !closed {
		t.Fatalf("test cleanup close = (%v, %v), want (true, nil)", closed, err)
	}
}

func TestRunAIDiscoveryReturnsAfterInventoryStoreCloses(t *testing.T) {
	service := newGatewayLifecycleDiscovery(t)
	store := service.InventoryStore()
	sidecar := &Sidecar{
		cfg:         config.DefaultConfig(),
		health:      NewSidecarHealth(),
		aiDiscovery: service,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sidecar.runAIDiscovery(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("runAIDiscovery error = %v, want context.Canceled", err)
	}
	if _, err := store.SchemaVersion(); err == nil {
		t.Fatal("runAIDiscovery returned before inventory store closed")
	}
}

func TestRunRestartableWaitsForShutdownAndPreservesError(t *testing.T) {
	sidecar := &Sidecar{}
	restart := make(chan struct{}, 1)
	entered := make(chan struct{})
	cancelObserved := make(chan struct{})
	releaseShutdown := make(chan struct{})
	wantErr := errors.New("inventory close failed")

	run := func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(cancelObserved)
		<-releaseShutdown
		return wantErr
	}
	outerCtx, outerCancel := context.WithCancel(context.Background())
	defer outerCancel()
	done := make(chan error, 1)
	go func() { done <- sidecar.runRestartable(outerCtx, "ai discovery", restart, run) }()
	awaitAIDiscoverySignal(t, entered, "first run startup")
	restart <- struct{}{}
	awaitAIDiscoverySignal(t, cancelObserved, "first run cancellation")

	select {
	case err := <-done:
		t.Fatalf("runRestartable returned before shutdown completed: %v", err)
	default:
	}
	close(releaseShutdown)
	if err := awaitAIDiscoveryResult(t, done, "shutdown error"); !errors.Is(err, wantErr) {
		t.Fatalf("runRestartable error = %v, want %v", err, wantErr)
	}
}

func TestRunRestartableStartsReplacementOnlyAfterCanceledRunStops(t *testing.T) {
	sidecar := &Sidecar{}
	restart := make(chan struct{}, 1)
	firstEntered := make(chan struct{})
	firstCanceled := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	calls := 0

	run := func(ctx context.Context) error {
		calls++
		if calls == 1 {
			close(firstEntered)
			<-ctx.Done()
			close(firstCanceled)
			<-releaseFirst
			return ctx.Err()
		}
		close(secondEntered)
		<-ctx.Done()
		return ctx.Err()
	}
	outerCtx, outerCancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sidecar.runRestartable(outerCtx, "ai discovery", restart, run) }()
	awaitAIDiscoverySignal(t, firstEntered, "first run startup")
	restart <- struct{}{}
	awaitAIDiscoverySignal(t, firstCanceled, "first run cancellation")
	select {
	case <-secondEntered:
		t.Fatal("replacement started before canceled run completed")
	default:
	}
	close(releaseFirst)
	awaitAIDiscoverySignal(t, secondEntered, "replacement startup")
	outerCancel()
	if err := awaitAIDiscoveryResult(t, done, "replacement shutdown"); !errors.Is(err, context.Canceled) {
		t.Fatalf("runRestartable shutdown error = %v, want context.Canceled", err)
	}
}
