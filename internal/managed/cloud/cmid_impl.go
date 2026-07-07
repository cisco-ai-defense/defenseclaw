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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Result codes returned by CMIDAPI functions. Mirrors cmid_result_e in
// CMIDAPI.h (Cisco does not ship the header alongside the dylib, so the
// values are duplicated here from the vendor documentation).
const (
	resSuccess         int32 = 0
	resGeneralError    int32 = -1
	resNotInited       int32 = -2
	resInvalidArg      int32 = -3
	resInsufficientLen int32 = -4
	resAgentError      int32 = -5
	resCloudError      int32 = -6
	resCloudFailure    int32 = -7
)

// retryDelays mirrors the wait ladder recommended by the CMIDAPI vendor
// documentation: three attempts with 10s, 20s, 30s incremental waits.
// Exposed as a package var so tests can shrink it via _test.go override.
var retryDelays = []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second}

// caller abstracts the OS-specific FFI shim. Each per-OS file provides
// newLibCaller(path) (caller, error); the shared impl below uses only
// this interface, keeping platform code minimal.
//
// The buf/buflen semantics mirror the CMIDAPI two-step sizing pattern:
// pass buf=nil to query the required size, then a suitably sized buffer
// to fetch the value. The C API sets *buflen to the required size on
// CMID_RES_INSUFFICIENT_LEN and to the copied size (including NUL) on
// CMID_RES_SUCCESS.
type caller interface {
	RefreshToken() int32
	GetID(buf []byte, buflen *int32) int32
	GetToken(buf []byte, buflen *int32) int32
	GetBusinessID(buf []byte, buflen *int32) int32
	GetURL(kind int32, buf []byte, buflen *int32) int32
	Close() error
}

// libProvider is the concrete Provider used on supported platforms. It
// caches values in memory and re-fetches only when Refresh or Invalidate
// is called (or when a getter is invoked with an empty cache).
type libProvider struct {
	path      string
	newCaller func(path string) (caller, error)
	log       *slog.Logger
	sleep     func(ctx context.Context, d time.Duration) error

	mu         sync.Mutex
	haveValues bool
	cmid       string
	token      string
	businessID string
	urls       map[URLKind]string
}

// Token implements Provider.
func (p *libProvider) Token(ctx context.Context) (string, error) {
	if err := p.ensureLoaded(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token, nil
}

// BusinessID implements Provider.
func (p *libProvider) BusinessID(ctx context.Context) (string, error) {
	if err := p.ensureLoaded(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.businessID, nil
}

// URL implements Provider.
func (p *libProvider) URL(ctx context.Context, kind URLKind) (string, error) {
	if err := p.ensureLoaded(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.urls[kind]; ok {
		return u, nil
	}
	return "", fmt.Errorf("cmid: unknown url kind %d: %w", kind, ErrInvalidArg)
}

// Refresh implements Provider.
func (p *libProvider) Refresh(ctx context.Context) error {
	return p.refreshOnce(ctx, true)
}

// Invalidate implements Provider.
func (p *libProvider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.haveValues = false
	p.cmid = ""
	p.token = ""
	p.businessID = ""
	p.urls = map[URLKind]string{}
}

func (p *libProvider) ensureLoaded(ctx context.Context) error {
	p.mu.Lock()
	loaded := p.haveValues
	p.mu.Unlock()
	if loaded {
		return nil
	}
	return p.refreshOnce(ctx, true)
}

// refreshOnce runs the full "open library → refresh_token → read values →
// close library" cycle, wrapping agent/cloud transport errors in the
// documented retry ladder. When callRefreshToken is false the caller is
// asking for a value-only reload (currently unused; hook for future
// consumers that already know the token is current).
func (p *libProvider) refreshOnce(ctx context.Context, callRefreshToken bool) error {
	var lastErr error
	for attempt := 0; attempt < len(retryDelays); attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		values, err := p.doRefresh(callRefreshToken)
		if err == nil {
			p.commit(values)
			return nil
		}
		lastErr = err
		// Only agent/cloud transport errors are retried. Everything else
		// (invalid arg, not-inited, cloud failure, unsupported platform)
		// is terminal.
		if !isTransientErr(err) {
			return err
		}
		if attempt == len(retryDelays)-1 {
			break
		}
		delay := retryDelays[attempt]
		if p.log != nil {
			p.log.Warn("cmid refresh failed, will retry",
				"attempt", attempt+1,
				"delay", delay,
				"err", err.Error(),
			)
		}
		if err := p.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return lastErr
}

// refreshedValues is the payload returned by a successful doRefresh.
type refreshedValues struct {
	cmid       string
	token      string
	businessID string
	urls       map[URLKind]string
}

// doRefresh performs a single load/read/unload cycle. It never sleeps.
func (p *libProvider) doRefresh(callRefreshToken bool) (refreshedValues, error) {
	c, err := p.newCaller(p.path)
	if err != nil {
		return refreshedValues{}, fmt.Errorf("cmid: open %s: %w", p.path, errors.Join(ErrNotAvailable, err))
	}
	defer func() {
		if cerr := c.Close(); cerr != nil && p.log != nil {
			p.log.Warn("cmid close failed", "err", cerr.Error())
		}
	}()

	if callRefreshToken {
		if rc := c.RefreshToken(); rc != resSuccess {
			return refreshedValues{}, mapResult(rc, "cmid_refresh_token")
		}
	}

	cmid, err := readString(c.GetID, "cmid_get_id")
	if err != nil {
		return refreshedValues{}, err
	}
	token, err := readString(c.GetToken, "cmid_get_token")
	if err != nil {
		return refreshedValues{}, err
	}
	bizID, err := readString(c.GetBusinessID, "cmid_get_business_id")
	if err != nil {
		return refreshedValues{}, err
	}
	urls := make(map[URLKind]string, 3)
	for _, kind := range []URLKind{URLKindEvent, URLKindCheckin, URLKindCatalog} {
		k := kind
		u, err := readString(func(buf []byte, n *int32) int32 {
			return c.GetURL(int32(k), buf, n)
		}, fmt.Sprintf("cmid_get_url(%d)", kind))
		if err != nil {
			return refreshedValues{}, err
		}
		urls[kind] = u
	}
	return refreshedValues{
		cmid:       cmid,
		token:      token,
		businessID: bizID,
		urls:       urls,
	}, nil
}

func (p *libProvider) commit(v refreshedValues) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cmid = v.cmid
	p.token = v.token
	p.businessID = v.businessID
	p.urls = v.urls
	p.haveValues = true
}

// readString implements the CMIDAPI two-step sizing pattern documented in
// CMIDAPI.h: probe with a nil buffer to learn the required size, then
// re-invoke with a buffer of that size. The returned string has the
// trailing NUL trimmed.
func readString(fn func(buf []byte, buflen *int32) int32, label string) (string, error) {
	var size int32
	if rc := fn(nil, &size); rc != resInsufficientLen {
		// The vendor docs say the size-query path returns
		// INSUFFICIENT_LEN. Anything else — including SUCCESS on a nil
		// buffer — is a protocol violation we surface as an error.
		return "", mapResult(rc, label+" [size]")
	}
	if size <= 0 {
		return "", fmt.Errorf("cmid: %s reported non-positive size %d: %w", label, size, ErrNotAvailable)
	}
	buf := make([]byte, size)
	n := size
	if rc := fn(buf, &n); rc != resSuccess {
		return "", mapResult(rc, label)
	}
	// Trim the terminating NUL (the API includes it in the copied bytes).
	trimmed := bytes.TrimRight(buf[:n], "\x00")
	return string(trimmed), nil
}

func mapResult(rc int32, label string) error {
	switch rc {
	case resSuccess:
		return nil
	case resNotInited:
		return fmt.Errorf("%s: not initialized: %w", label, ErrNotAvailable)
	case resInvalidArg:
		return fmt.Errorf("%s: invalid arg: %w", label, ErrInvalidArg)
	case resInsufficientLen:
		return fmt.Errorf("%s: insufficient buffer: %w", label, ErrInvalidArg)
	case resAgentError:
		return fmt.Errorf("%s: agent error: %w", label, ErrAgentUnavailable)
	case resCloudError:
		return fmt.Errorf("%s: cloud transport error: %w", label, ErrAgentUnavailable)
	case resCloudFailure:
		return fmt.Errorf("%s: cloud failure: %w", label, ErrCloudFailure)
	case resGeneralError:
		return fmt.Errorf("%s: general error: %w", label, ErrNotAvailable)
	default:
		return fmt.Errorf("%s: unknown result code %d: %w", label, rc, ErrNotAvailable)
	}
}

func isTransientErr(err error) bool {
	return errors.Is(err, ErrAgentUnavailable)
}
