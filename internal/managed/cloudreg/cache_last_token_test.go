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
	"testing"
	"time"
)

func TestLastTokenAtTracksCachedAndFetchedTokens(t *testing.T) {
	inner := &fakeProvider{token: "t"}
	if !LastTokenAt(inner).IsZero() {
		t.Fatal("an unwrapped provider reported a token time")
	}
	cached := WithTokenCache(inner, time.Minute)
	if !LastTokenAt(cached).IsZero() {
		t.Fatal("a provider that gave no token reported a token time")
	}
	before := time.Now()
	if _, err := cached.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetched := LastTokenAt(cached)
	if fetched.Before(before) {
		t.Fatalf("fetch time %s before %s", fetched, before)
	}
	if _, err := cached.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if LastTokenAt(cached).Before(fetched) {
		t.Fatal("a cache hit did not advance the token time")
	}
	inner.token = ""
	cached.Invalidate()
	at := LastTokenAt(cached)
	if _, err := cached.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !LastTokenAt(cached).Equal(at) {
		t.Fatal("an empty token advanced the token time")
	}
}
