// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cloud

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveDylib exercises the real Cisco Cloud Management dylib. It only
// runs when DEFENSECLAW_CMID_LIVE=1 is set, so it never runs in CI and
// never interferes with developers who don't have Secure Client installed.
//
// Run locally with:
//
//	DEFENSECLAW_CMID_LIVE=1 go test -run TestLiveDylib -v ./internal/managed/cloud/...
func TestLiveDylib(t *testing.T) {
	if os.Getenv("DEFENSECLAW_CMID_LIVE") != "1" {
		t.Skip("set DEFENSECLAW_CMID_LIVE=1 to run against the real Cisco dylib")
	}
	// The default path is what ships with Secure Client; allow override
	// for developers who relocated the module.
	p := NewProvider(Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := p.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	tok, err := p.Token(ctx)
	if err != nil || tok == "" {
		t.Fatalf("Token = %q err = %v", tok, err)
	}
	bid, err := p.BusinessID(ctx)
	if err != nil || bid == "" {
		t.Fatalf("BusinessID = %q err = %v", bid, err)
	}
	for _, kind := range []URLKind{URLKindEvent, URLKindCheckin, URLKindCatalog} {
		u, err := p.URL(ctx, kind)
		if err != nil || u == "" {
			t.Fatalf("URL(%d) = %q err = %v", kind, u, err)
		}
	}
	// Cached second read should not error.
	if _, err := p.Token(ctx); err != nil {
		t.Fatalf("cached Token: %v", err)
	}
}
