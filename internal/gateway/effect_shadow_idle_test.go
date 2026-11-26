// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-11:GAP-1913. A hook call starts its effect-shadow run on a
// goroutine of its own (scheduleEffectShadow) that nothing in a test waits
// for, and that run reads the state hookpaths keeps for its test overrides
// (the network-share functions, the parent-step switch) with no lock: the
// product reads them only after a test or the process set them. A test that
// then sets or restores an override while an earlier test's run is still in
// flight is a data race, which -race reports in whichever shard happens to put
// the two tests together.
//
// The shadow run is bounded (effectShadowMaxConcurrent slots, a time cap), so
// the product has no leak. The seam is the slot channel: withEffectShadowIdle
// takes every slot, which waits for each run in flight (a run frees its slot
// after it read, so the receive happens before the send that takes the slot)
// and keeps a new run from starting (a hook call that finds the slots busy
// drops its run, as it does under load), runs f, then frees the slots (the
// receive happens before the next run's send, so f happens before its reads).
// Every gateway test sets and restores a hookpaths override through the
// *Idle wrappers below, and TestGAP1913GatewayTestsSetHookpathsOverridesIdle
// fails a test file that calls one directly.

// effectShadowIdleMu keeps two tests from each holding some of the slots and
// waiting for the rest.
var effectShadowIdleMu sync.Mutex

// effectShadowIdleWait is how long withEffectShadowIdle waits for the runs in
// flight; a run is bounded by counted work (DET111 FIX-T19) plus the time a
// test's own share probe holds it, so this is far above any run that is not
// stuck.
const effectShadowIdleWait = 30 * time.Second

// withEffectShadowIdle runs f while no effect-shadow run is in flight and none
// can start. When a run does not finish in effectShadowIdleWait the test fails
// with that said, and f still runs (the restore of an override must not be
// skipped).
func withEffectShadowIdle(t testing.TB, f func()) {
	t.Helper()
	effectShadowIdleMu.Lock()
	defer effectShadowIdleMu.Unlock()
	timer := time.NewTimer(effectShadowIdleWait)
	defer timer.Stop()
	held := 0
	defer func() {
		for ; held > 0; held-- {
			<-effectShadowSlots
		}
	}()
	for held < effectShadowMaxConcurrent {
		select {
		case effectShadowSlots <- struct{}{}:
			held++
		case <-timer.C:
			t.Errorf("%d effect-shadow run(s) did not finish in %s; the hookpaths override is changed while they may still read it",
				effectShadowMaxConcurrent-held, effectShadowIdleWait)
			f()
			return
		}
	}
	f()
}

// idleOverride sets a hookpaths test override with every shadow run idle and
// returns its restore, which also waits for the runs.
func idleOverride(t testing.TB, set func() (restore func())) (restore func()) {
	t.Helper()
	var undo func()
	withEffectShadowIdle(t, func() { undo = set() })
	return func() { withEffectShadowIdle(t, undo) }
}

func overrideNetworkSharesIdle(t testing.TB, rootOf func(path string) string, ask func(root string)) func() {
	t.Helper()
	return idleOverride(t, func() func() { return hookpaths.OverrideNetworkSharesForTest(rootOf, ask) })
}

func overrideRemoteSharesIdle(t testing.TB, ask func(root string), thisMachine func(root string) bool) func() {
	t.Helper()
	return idleOverride(t, func() func() { return hookpaths.OverrideRemoteSharesForTest(ask, thisMachine) })
}

func observeRemoteShareReadsIdle(t testing.TB, note func(name string)) func() {
	t.Helper()
	return idleOverride(t, func() func() { return hookpaths.ObserveRemoteShareReadsForTest(note) })
}

func holdKnownFolderReadsIdle(t testing.TB, hold func(folder string) bool, wait time.Duration) func() {
	t.Helper()
	return idleOverride(t, func() func() { return hookpaths.HoldKnownFolderReadsForTest(hold, wait) })
}

// setIdle sets *p to v with every shadow run idle and returns the restore of
// the value it replaced, which also waits for the runs.
func setIdle[T any](t testing.TB, p *T, v T) (restore func()) {
	t.Helper()
	var prev T
	withEffectShadowIdle(t, func() { prev, *p = *p, v })
	return func() { withEffectShadowIdle(t, func() { *p = prev }) }
}

// The two gateway variables a shadow run reads (effectResolverOverride,
// effectShadowFaultHook) are set and restored only through these, so a test
// never writes one while a run of an earlier test reads it. The run has no
// time cap variable since DET111 FIX-T19.

func setEffectResolverIdle(t testing.TB, resolver func(string) (string, bool)) func() {
	t.Helper()
	return setIdle(t, &effectResolverOverride, resolver)
}

func setEffectShadowFaultHookIdle(t testing.TB, hook func()) func() {
	t.Helper()
	return setIdle(t, &effectShadowFaultHook, hook)
}

// A shadow run in flight keeps an override from being set until it finished,
// and the run's reads happen before the override.
func TestGAP1913OverrideWaitsForAShadowRunInFlight(t *testing.T) {
	hold := make(chan struct{})
	var finished atomic.Bool
	// The hook variable is read by every run, so it is set with them idle too.
	t.Cleanup(setEffectShadowFaultHookIdle(t, func() { <-hold }))
	scheduleEffectShadow(shadowLiveRequest(shadowLiveWrite), effectRulesShadow, tierRestricted,
		func(EffectShadowResult) { finished.Store(true) })
	if len(effectShadowSlots) == 0 {
		t.Fatal("the shadow run did not start (every slot was busy)")
	}
	returned := make(chan bool, 1)
	go func() {
		restore := overrideNetworkSharesIdle(t, func(string) string { return "" }, func(string) {})
		returned <- finished.Load()
		restore()
	}()
	select {
	case <-returned:
		close(hold)
		t.Fatal("the override was set while a shadow run was still in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(hold)
	select {
	case ranFirst := <-returned:
		if !ranFirst {
			t.Fatal("the override returned before the shadow run finished")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the override never returned after the shadow run finished")
	}
}

// Two tests that set an override at once cannot each hold part of the slots.
func TestGAP1913ConcurrentOverridesDoNotDeadlock(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			withEffectShadowIdle(t, func() {})
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent withEffectShadowIdle calls did not finish")
	}
	// A run an earlier test left in flight holds a slot until it read, so wait
	// for the slots to come back before asserting that none stayed held.
	for deadline := time.Now().Add(effectShadowIdleWait); len(effectShadowSlots) != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d slot(s) left held", len(effectShadowSlots))
		}
	}
}

// No gateway test sets a hookpaths test override directly: the override goes
// through the *Idle wrappers above, or an earlier test's shadow run races it.
// The same holds for the two gateway variables a shadow run reads
// (effectResolverOverride, effectShadowFaultHook): a test writes them through
// setEffectResolverIdle and setEffectShadowFaultHookIdle only. A read of one
// is fine.
// TestMain sets its overrides before any test and marks the line gap1913-ok.
func TestGAP1913GatewayTestsSetHookpathsOverridesIdle(t *testing.T) {
	// The only files that may set an override: the wrappers themselves. The
	// second holds the one wrapper whose caller is !windows (see its comment).
	idleWrapperFiles := map[string]bool{
		"effect_shadow_idle_test.go":      true,
		"effect_shadow_idle_unix_test.go": true,
	}
	direct := regexp.MustCompile(`hookpaths\.(\w+ForTests?|SetParentStepIsText)\(`)
	const shadowVars = `(?:effectResolverOverride|effectShadowFaultHook)`
	// An assignment (=, :=, +=, ++ and the like) or the address taken for a write.
	directVar := regexp.MustCompile(`\b` + shadowVars + `\b\s*(?:=[^=]|:=|[-+*/|&^%]=|\+\+|--)|&\s*` + shadowVars + `\b`)
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no gateway test files read: %v", err)
	}
	for _, file := range files {
		if idleWrapperFiles[file] {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if direct.MatchString(line) && !strings.Contains(line, "gap1913-ok") {
				t.Errorf("%s:%d sets a hookpaths override directly (rel-1-0-11:GAP-1913): use the *Idle wrapper of effect_shadow_idle_test.go", file, n+1)
			}
			if directVar.MatchString(line) && !strings.Contains(line, "gap1913-ok") {
				t.Errorf("%s:%d writes an effect-shadow variable directly (rel-1-0-11:GAP-1954): use the set*Idle helper of effect_shadow_idle_test.go", file, n+1)
			}
		}
	}
}
