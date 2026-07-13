// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cloudreg

import (
	"context"
	"errors"
	"testing"
)

type fakeProvider struct {
	token string
}

func (f *fakeProvider) Token(context.Context) (string, error) { return f.token, nil }
func (f *fakeProvider) Refresh(context.Context) error         { return nil }
func (f *fakeProvider) Invalidate()                           { f.token = "" }

func TestNewWithoutFactoryReturnsSentinel(t *testing.T) {
	// Save and restore package state so this test is order-independent.
	mu.Lock()
	orig := factory
	factory = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		factory = orig
		mu.Unlock()
	})

	_, err := New(Config{})
	if !errors.Is(err, ErrNoProviderRegistered) {
		t.Fatalf("New err = %v, want ErrNoProviderRegistered", err)
	}
}

func TestRegisterAndNew(t *testing.T) {
	mu.Lock()
	orig := factory
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		factory = orig
		mu.Unlock()
	})

	Register(func(cfg Config) (Provider, error) {
		return &fakeProvider{token: "t-" + cfg.LibPath}, nil
	})
	p, err := New(Config{LibPath: "abc"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "t-abc" {
		t.Fatalf("Token = %q, want %q", tok, "t-abc")
	}
}
