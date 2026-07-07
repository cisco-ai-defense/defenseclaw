// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCaller is a scriptable caller for tests. It records how many times
// it was constructed (via constructor closure) and how many times each
// method was called, and supports failing RefreshToken a configurable
// number of times.
type fakeCaller struct {
	mu sync.Mutex

	// refreshFailures decrements on each RefreshToken call until zero,
	// returning refreshErrCode meanwhile.
	refreshFailures int32
	refreshErrCode  int32

	values     map[string]string // "id", "token", "bid", "url1", "url2", "url3"
	closeErr   error
	closeCount int32

	// hooks let individual tests intercept a call.
	beforeRefresh func()
}

func newFakeCaller(vals map[string]string) *fakeCaller {
	if vals == nil {
		vals = map[string]string{
			"id":    "cmid-abc123",
			"token": "token-xyz",
			"bid":   "biz-42",
			"url1":  "https://event.example",
			"url2":  "https://checkin.example",
			"url3":  "https://catalog.example",
		}
	}
	return &fakeCaller{values: vals}
}

func (f *fakeCaller) RefreshToken() int32 {
	if f.beforeRefresh != nil {
		f.beforeRefresh()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshFailures > 0 {
		f.refreshFailures--
		return f.refreshErrCode
	}
	return resSuccess
}

func (f *fakeCaller) fill(buf []byte, buflen *int32, val string) int32 {
	if buflen == nil {
		return resInvalidArg
	}
	needed := int32(len(val)) + 1
	if buf == nil {
		*buflen = needed
		return resInsufficientLen
	}
	if *buflen < needed {
		*buflen = needed
		return resInsufficientLen
	}
	copy(buf, val)
	buf[len(val)] = 0
	*buflen = needed
	return resSuccess
}

func (f *fakeCaller) GetID(buf []byte, buflen *int32) int32 {
	return f.fill(buf, buflen, f.values["id"])
}

func (f *fakeCaller) GetToken(buf []byte, buflen *int32) int32 {
	return f.fill(buf, buflen, f.values["token"])
}

func (f *fakeCaller) GetBusinessID(buf []byte, buflen *int32) int32 {
	return f.fill(buf, buflen, f.values["bid"])
}

func (f *fakeCaller) GetURL(kind int32, buf []byte, buflen *int32) int32 {
	key := fmt.Sprintf("url%d", kind)
	val, ok := f.values[key]
	if !ok {
		return resInvalidArg
	}
	return f.fill(buf, buflen, val)
}

func (f *fakeCaller) Close() error {
	atomic.AddInt32(&f.closeCount, 1)
	return f.closeErr
}

func newTestProvider(t *testing.T, fake *fakeCaller, sleep func(context.Context, time.Duration) error) *libProvider {
	t.Helper()
	if sleep == nil {
		sleep = func(context.Context, time.Duration) error { return nil }
	}
	p := &libProvider{
		path: "/tmp/fake-libcmidapi",
		newCaller: func(string) (caller, error) {
			return fake, nil
		},
		log:   slog.New(slog.DiscardHandler),
		sleep: sleep,
		urls:  map[URLKind]string{},
	}
	return p
}

func TestRefreshHappyPath(t *testing.T) {
	fake := newFakeCaller(nil)
	p := newTestProvider(t, fake, nil)
	ctx := context.Background()

	tok, err := p.Token(ctx)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "token-xyz" {
		t.Fatalf("Token = %q, want %q", tok, "token-xyz")
	}
	bid, err := p.BusinessID(ctx)
	if err != nil || bid != "biz-42" {
		t.Fatalf("BusinessID = %q err=%v", bid, err)
	}
	u, err := p.URL(ctx, URLKindEvent)
	if err != nil || u != "https://event.example" {
		t.Fatalf("URL(event) = %q err=%v", u, err)
	}
	if got := atomic.LoadInt32(&fake.closeCount); got != 1 {
		t.Fatalf("closeCount after first read = %d, want 1 (one open/close cycle)", got)
	}
	// Second Token call must hit cache — no new refresh, so closeCount unchanged.
	if _, err := p.Token(ctx); err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if got := atomic.LoadInt32(&fake.closeCount); got != 1 {
		t.Fatalf("closeCount after cached read = %d, want 1", got)
	}
}

func TestInvalidateForcesReload(t *testing.T) {
	fake := newFakeCaller(nil)
	p := newTestProvider(t, fake, nil)
	ctx := context.Background()

	if _, err := p.Token(ctx); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	p.Invalidate()
	if _, err := p.Token(ctx); err != nil {
		t.Fatalf("post-invalidate Token: %v", err)
	}
	if got := atomic.LoadInt32(&fake.closeCount); got != 2 {
		t.Fatalf("closeCount = %d, want 2 after Invalidate + read", got)
	}
}

func TestRefreshRetryLadder(t *testing.T) {
	fake := newFakeCaller(nil)
	fake.refreshFailures = 2
	fake.refreshErrCode = resAgentError

	var sleeps []time.Duration
	sleep := func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	p := newTestProvider(t, fake, sleep)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if want := []time.Duration{10 * time.Second, 20 * time.Second}; !equalDurations(sleeps, want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	if got := atomic.LoadInt32(&fake.closeCount); got != 3 {
		t.Fatalf("closeCount = %d, want 3 (one per attempt)", got)
	}
}

func TestRefreshGivesUpAfterMaxRetries(t *testing.T) {
	fake := newFakeCaller(nil)
	fake.refreshFailures = 10
	fake.refreshErrCode = resAgentError
	p := newTestProvider(t, fake, func(context.Context, time.Duration) error { return nil })

	err := p.Refresh(context.Background())
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("Refresh err = %v, want ErrAgentUnavailable", err)
	}
	if got := atomic.LoadInt32(&fake.closeCount); got != int32(len(retryDelays)) {
		t.Fatalf("closeCount = %d, want %d", got, len(retryDelays))
	}
}

func TestRefreshTerminalErrorSkipsRetry(t *testing.T) {
	// CMID_RES_CLOUD_FAILURE is terminal — the retry ladder must not fire.
	fake := newFakeCaller(nil)
	fake.refreshFailures = 3
	fake.refreshErrCode = resCloudFailure

	var sleepCount int
	sleep := func(context.Context, time.Duration) error {
		sleepCount++
		return nil
	}
	p := newTestProvider(t, fake, sleep)

	err := p.Refresh(context.Background())
	if !errors.Is(err, ErrCloudFailure) {
		t.Fatalf("Refresh err = %v, want ErrCloudFailure", err)
	}
	if sleepCount != 0 {
		t.Fatalf("sleepCount = %d, want 0 (terminal error must not retry)", sleepCount)
	}
}

func TestRefreshRespectsCanceledContext(t *testing.T) {
	fake := newFakeCaller(nil)
	fake.refreshFailures = 10
	fake.refreshErrCode = resAgentError

	ctx, cancel := context.WithCancel(context.Background())
	sleep := func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	p := newTestProvider(t, fake, sleep)

	err := p.Refresh(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh err = %v, want context.Canceled", err)
	}
}

func TestOpenLibFailureWrapsErrNotAvailable(t *testing.T) {
	p := &libProvider{
		path: "/nope",
		newCaller: func(string) (caller, error) {
			return nil, errors.New("dlopen: file not found")
		},
		log:   slog.New(slog.DiscardHandler),
		sleep: func(context.Context, time.Duration) error { return nil },
		urls:  map[URLKind]string{},
	}
	_, err := p.Token(context.Background())
	if !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("Token err = %v, want ErrNotAvailable wrapped", err)
	}
	if !strings.Contains(err.Error(), "/nope") {
		t.Fatalf("Token err = %v, want it to mention the path", err)
	}
}

func TestReadStringHandlesTwoStepSizing(t *testing.T) {
	// Directly exercise readString: first call must be size-query with
	// nil buffer, second call must be with an appropriately sized buffer.
	var calls int
	var sizeSeen int32
	fn := func(buf []byte, buflen *int32) int32 {
		calls++
		val := "hello"
		needed := int32(len(val)) + 1
		if buf == nil {
			*buflen = needed
			sizeSeen = needed
			return resInsufficientLen
		}
		if *buflen != needed {
			return resInvalidArg
		}
		copy(buf, val)
		buf[len(val)] = 0
		*buflen = needed
		return resSuccess
	}
	got, err := readString(fn, "unit")
	if err != nil {
		t.Fatalf("readString: %v", err)
	}
	if got != "hello" {
		t.Fatalf("readString = %q, want %q", got, "hello")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (probe + fetch)", calls)
	}
	if sizeSeen != 6 {
		t.Fatalf("size buflen = %d, want 6", sizeSeen)
	}
}

func TestMapResultErrorMappings(t *testing.T) {
	cases := []struct {
		rc      int32
		wantErr error
	}{
		{resSuccess, nil},
		{resNotInited, ErrNotAvailable},
		{resInvalidArg, ErrInvalidArg},
		{resInsufficientLen, ErrInvalidArg},
		{resAgentError, ErrAgentUnavailable},
		{resCloudError, ErrAgentUnavailable},
		{resCloudFailure, ErrCloudFailure},
		{resGeneralError, ErrNotAvailable},
		{99, ErrNotAvailable}, // unknown code
	}
	for _, tc := range cases {
		got := mapResult(tc.rc, "label")
		if tc.wantErr == nil {
			if got != nil {
				t.Errorf("mapResult(%d) = %v, want nil", tc.rc, got)
			}
			continue
		}
		if !errors.Is(got, tc.wantErr) {
			t.Errorf("mapResult(%d) = %v, want wrap of %v", tc.rc, got, tc.wantErr)
		}
	}
}

func TestResolveLibPathPrecedence(t *testing.T) {
	// Explicit config wins over env and default.
	t.Setenv("DEFENSECLAW_CMID_LIB_PATH", "/env/path")
	if got := resolveLibPath(Config{LibPath: "/explicit"}); got != "/explicit" {
		t.Errorf("resolveLibPath explicit = %q, want /explicit", got)
	}
	if got := resolveLibPath(Config{}); got != "/env/path" {
		t.Errorf("resolveLibPath env = %q, want /env/path", got)
	}
	t.Setenv("DEFENSECLAW_CMID_LIB_PATH", "")
	if got := resolveLibPath(Config{}); got != defaultLibPath {
		t.Errorf("resolveLibPath default = %q, want %q", got, defaultLibPath)
	}
}

func TestUnknownURLKindIsInvalidArg(t *testing.T) {
	fake := newFakeCaller(nil)
	p := newTestProvider(t, fake, nil)
	_, err := p.URL(context.Background(), URLKind(99))
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("URL(99) err = %v, want ErrInvalidArg", err)
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
