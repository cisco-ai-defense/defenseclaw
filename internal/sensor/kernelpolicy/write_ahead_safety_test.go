// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"os"
	"testing"
)

func TestAmbiguousAddKeepsThePolicyInTheCleanupRecord(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.tg.failAfterAdd = true
	h.pass()
	loaded := h.tg.names()
	if len(loaded) == 0 {
		t.Fatal("fixture did not load a policy before losing the response")
	}
	recorded := h.loadedFile()
	if len(recorded) != len(loaded) {
		t.Fatalf("loaded names %v, durable cleanup record %v", loaded, recorded)
	}
	h.tg.failAfterAdd = false
	if _, err := Cleanup(context.Background(), h.tg, h.dirs); err != nil {
		t.Fatal(err)
	}
	if len(h.tg.names()) != 0 {
		t.Fatalf("cleanup left policies: %v", h.tg.names())
	}
}

func TestAFailedRecordWriteCannotAuthorizeANewAdd(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	if err := os.MkdirAll(h.dirs.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.dirs.Loaded(), 0o700); err != nil {
		t.Fatal(err)
	}
	const name = "defenseclaw-controls-deadbeef"
	if err := h.ctl.recordLoaded(name); err == nil {
		t.Fatal("the write-ahead record unexpectedly succeeded")
	}
	if h.ctl.recorded[name] {
		t.Fatal("a failed disk write marked the name as durably recorded")
	}
	h.pass()
	if len(h.tg.names()) != 0 {
		t.Fatalf("policy loaded before its record was durable: %v", h.tg.names())
	}
	if err := os.Remove(h.dirs.Loaded()); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if loaded, recorded := h.tg.names(), h.loadedFile(); len(loaded) == 0 || len(loaded) != len(recorded) {
		t.Fatalf("loaded names %v, durable cleanup record %v", loaded, recorded)
	}
}
