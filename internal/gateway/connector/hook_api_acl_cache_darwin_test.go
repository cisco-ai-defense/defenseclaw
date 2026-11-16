// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"testing"
	"time"
)

const cleanDarwinACLListing = "drwx------  3 user  staff  96 Nov  2 10:00 /x\n"

func TestHookAPIACLInspectionRetriesTimeoutOnce(t *testing.T) {
	attempts := 0
	inspect := func(ctx context.Context, _ string) ([]byte, error) {
		attempts++
		if attempts == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []byte(cleanDarwinACLListing), nil
	}
	if err := hookAPIValidateDirectoryACLRetrying("/x", 10*time.Millisecond, inspect); err != nil {
		t.Fatalf("a single timeout failed the request: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want one retry", attempts)
	}
}

func TestHookAPIACLInspectionFailsOnASecondTimeout(t *testing.T) {
	attempts := 0
	inspect := func(ctx context.Context, _ string) ([]byte, error) {
		attempts++
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := hookAPIValidateDirectoryACLRetrying("/x", 10*time.Millisecond, inspect); err == nil {
		t.Fatal("two timeouts passed the ACL check")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want exactly one retry", attempts)
	}
}
