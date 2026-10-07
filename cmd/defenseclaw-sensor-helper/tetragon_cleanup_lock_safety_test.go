//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

func TestCleanupRefusesWhenTheReconcilerLockIsUnavailable(t *testing.T) {
	dirs := cleanupDirs(t, recordedObserve)
	if err := os.Mkdir(dirs.Lock(), 0o700); err != nil {
		t.Fatal(err)
	}
	fake := &cleanupFake{loaded: map[string]bool{recordedObserve: true}}
	dial := func(context.Context) (kernelpolicy.Client, func(), error) {
		t.Fatal("cleanup without the lock must not reach Tetragon")
		return fake, nil, nil
	}
	var out bytes.Buffer
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, dial); code != cleanupFailed {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
