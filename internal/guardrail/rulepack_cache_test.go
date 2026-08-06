// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func countingRulePackLoader() (func(string) (*RulePack, error), *sync.Map) {
	counts := &sync.Map{}
	loader := func(dir string) (*RulePack, error) {
		value, _ := counts.LoadOrStore(dir, new(int64))
		atomic.AddInt64(value.(*int64), 1)
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}, nil
	}
	return loader, counts
}

func rulePackLoadCount(counts *sync.Map, dir string) int64 {
	value, ok := counts.Load(dir)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(value.(*int64))
}

func mustCacheLoad(t *testing.T, cache *RulePackCache, dir string) *RulePack {
	t.Helper()
	pack, err := cache.Load(dir)
	if err != nil {
		t.Fatalf("cache.Load(%q): %v", dir, err)
	}
	if pack == nil {
		t.Fatalf("cache.Load(%q) returned nil without error", dir)
	}
	return pack
}

func TestRulePackCacheCachesSuccessByNormalizedDirectory(t *testing.T) {
	loader, counts := countingRulePackLoader()
	cache := newRulePackCacheWithLoader(loader)

	first := mustCacheLoad(t, cache, "/policies/strict")
	for _, equivalent := range []string{
		"/policies/strict",
		"/policies/strict/",
		"/policies/./strict",
	} {
		if got := mustCacheLoad(t, cache, equivalent); got != first {
			t.Fatalf("%q returned a different cached pointer", equivalent)
		}
	}
	total := rulePackLoadCount(counts, "/policies/strict") +
		rulePackLoadCount(counts, "/policies/strict/") +
		rulePackLoadCount(counts, "/policies/./strict")
	if total != 1 {
		t.Fatalf("equivalent paths triggered %d loads, want 1", total)
	}

	second := mustCacheLoad(t, cache, "/policies/permissive")
	if second == first {
		t.Fatal("distinct directories returned one cached pointer")
	}
	if got := rulePackLoadCount(counts, "/policies/permissive"); got != 1 {
		t.Fatalf("permissive loads = %d, want 1", got)
	}
}

func TestRulePackCacheEmptyDirectoryUsesEmbeddedDefaults(t *testing.T) {
	cache := NewRulePackCache()
	first := mustCacheLoad(t, cache, "")
	second := mustCacheLoad(t, cache, "")
	if first != second {
		t.Fatal("embedded defaults were not cached")
	}
	if first.ExfilJudge() == nil || first.Suppressions == nil || first.SensitiveTools == nil {
		t.Fatal("cached embedded defaults are incomplete")
	}
}

func TestRulePackCacheDoesNotCacheFailuresAndLoadsRepair(t *testing.T) {
	var calls atomic.Int64
	repaired := atomic.Bool{}
	expected := &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	loader := func(string) (*RulePack, error) {
		calls.Add(1)
		if !repaired.Load() {
			return nil, &RulePackError{Path: "rules/custom.yaml", Code: "yaml_invalid", Reason: "invalid YAML"}
		}
		return expected, nil
	}
	cache := newRulePackCacheWithLoader(loader)

	if pack, err := cache.Load("/pack"); err == nil || pack != nil {
		t.Fatalf("failed load = (%v, %v), want (nil, error)", pack, err)
	}
	repaired.Store(true)
	if got := mustCacheLoad(t, cache, "/pack"); got != expected {
		t.Fatal("repaired pack was not loaded")
	}
	if got := mustCacheLoad(t, cache, "/pack"); got != expected {
		t.Fatal("successful repair was not cached")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls = %d, want failed attempt + repair", got)
	}
}

func TestRulePackCacheConcurrentSameDirectorySharesSuccess(t *testing.T) {
	var calls atomic.Int64
	expected := &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	loader := func(string) (*RulePack, error) {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond)
		return expected, nil
	}
	cache := newRulePackCacheWithLoader(loader)

	const goroutines = 64
	results := make([]*RulePack, goroutines)
	errs := make([]error, goroutines)
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for index := 0; index < goroutines; index++ {
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = cache.Load("/pack")
		}(index)
	}
	wait.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent success triggered %d loads, want 1", got)
	}
	for index := range results {
		if errs[index] != nil || results[index] != expected {
			t.Fatalf("result %d = (%p, %v), want (%p, nil)", index, results[index], errs[index], expected)
		}
	}
}

func TestRulePackCacheConcurrentSameDirectorySharesAttemptButNotFailureCache(t *testing.T) {
	var calls atomic.Int64
	start := make(chan struct{})
	release := make(chan struct{})
	loadErr := errors.New("temporary load failure")
	loader := func(string) (*RulePack, error) {
		if calls.Add(1) == 1 {
			close(start)
		}
		<-release
		return nil, loadErr
	}
	cache := newRulePackCacheWithLoader(loader)

	const goroutines = 32
	errs := make([]error, goroutines)
	var wait sync.WaitGroup
	wait.Add(goroutines)
	go func() {
		defer wait.Done()
		_, errs[0] = cache.Load("/pack")
	}()
	<-start

	for index := 1; index < goroutines; index++ {
		go func(index int) {
			defer wait.Done()
			_, errs[index] = cache.Load("/pack")
		}(index)
	}

	deadline := time.Now().Add(time.Second)
	for {
		cache.mu.Lock()
		pending := cache.inflight[normalizeRulePackDir("/pack")]
		followers := 0
		if pending != nil {
			followers = pending.followers
		}
		cache.mu.Unlock()
		if followers == goroutines-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d callers joined the in-flight attempt", followers, goroutines-1)
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	wait.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent failed attempt triggered %d loads, want 1", got)
	}
	for index, err := range errs {
		if !errors.Is(err, loadErr) {
			t.Fatalf("error %d = %v, want shared failure", index, err)
		}
	}

	if _, err := cache.Load("/pack"); !errors.Is(err, loadErr) {
		t.Fatalf("retry error = %v, want loader failure", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("failure remained cached; calls = %d, want 2", got)
	}
}

func TestRulePackCacheDistinctDirectoriesLoadInParallel(t *testing.T) {
	const directories = 8
	entered := make(chan struct{}, directories)
	release := make(chan struct{})
	loader := func(string) (*RulePack, error) {
		entered <- struct{}{}
		<-release
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}, nil
	}
	cache := newRulePackCacheWithLoader(loader)

	var wait sync.WaitGroup
	wait.Add(directories)
	for index := 0; index < directories; index++ {
		go func(index int) {
			defer wait.Done()
			_, _ = cache.Load(fmt.Sprintf("/pack/%d", index))
		}(index)
	}
	for index := 0; index < directories; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("distinct-directory loads serialized behind the cache mutex")
		}
	}
	close(release)
	wait.Wait()
}

func TestRulePackCacheLoaderPanicReleasesWaitersAndAllowsRetry(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	const privatePanicValue = "private loader panic value"
	expected := &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	loader := func(string) (*RulePack, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			panic(privatePanicValue)
		}
		return expected, nil
	}
	cache := newRulePackCacheWithLoader(loader)

	ownerResult := make(chan error, 1)
	go func() {
		_, err := cache.Load("/pack")
		ownerResult <- err
	}()
	<-started

	cache.mu.Lock()
	pending := cache.inflight[normalizeRulePackDir("/pack")]
	cache.mu.Unlock()
	if pending == nil {
		t.Fatal("panicking load was not registered as in-flight")
	}

	waiterResult := make(chan error, 1)
	go func() {
		<-pending.ready
		waiterResult <- pending.err
	}()
	close(release)

	select {
	case err := <-ownerResult:
		requireRulePackError(t, err, "loader_panic")
		if strings.Contains(err.Error(), privatePanicValue) {
			t.Fatalf("loader panic error leaked panic value: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("triggering caller was not released after loader panic")
	}
	select {
	case err := <-waiterResult:
		requireRulePackError(t, err, "loader_panic")
		if strings.Contains(err.Error(), privatePanicValue) {
			t.Fatalf("waiter error leaked panic value: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight waiter was not released after loader panic")
	}

	cache.mu.Lock()
	_, stillInflight := cache.inflight[normalizeRulePackDir("/pack")]
	_, cached := cache.packs[normalizeRulePackDir("/pack")]
	cache.mu.Unlock()
	if stillInflight || cached {
		t.Fatalf("panicked load poisoned cache state: inflight=%v cached=%v", stillInflight, cached)
	}
	if got := mustCacheLoad(t, cache, "/pack"); got != expected {
		t.Fatal("retry after loader panic returned an unexpected pack")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls = %d, want panic + retry", got)
	}
}

func TestRulePackCacheNilLoaderAndNilResult(t *testing.T) {
	if cache := newRulePackCacheWithLoader(nil); cache.loader == nil {
		t.Fatal("nil loader did not select LoadRulePack")
	}
	cache := newRulePackCacheWithLoader(func(string) (*RulePack, error) { return nil, nil })
	pack, err := cache.Load("/pack")
	if pack != nil {
		t.Fatalf("nil loader result produced pack %p", pack)
	}
	requireRulePackError(t, err, "loader_nil")
}
