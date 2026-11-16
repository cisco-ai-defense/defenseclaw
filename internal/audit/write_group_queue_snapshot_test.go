// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

func TestR109PerfWALWriteQueueDepthAndAge(t *testing.T) {
	var group writeGroup
	started := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	second := make(chan error, 1)
	execute := func(batch []*groupedWrite) {
		close(started)
		<-release
	}
	go func() { first <- group.do(&groupedWrite{ctx: context.Background()}, execute) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first batch did not start")
	}
	go func() { second <- group.do(&groupedWrite{ctx: context.Background()}, func([]*groupedWrite) {}) }()
	deadline := time.Now().Add(time.Second)
	for group.snapshot(time.Now()).Depth != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := group.snapshot(time.Now().Add(20 * time.Millisecond))
	if snapshot.Depth != 1 || snapshot.OldestAge < 20*time.Millisecond {
		t.Fatalf("pending queue = %+v", snapshot)
	}
	close(release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first batch did not finish")
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second batch did not finish")
	}
	if snapshot := group.snapshot(time.Now()); snapshot != (WriteQueueSnapshot{}) {
		t.Fatalf("drained queue = %+v", snapshot)
	}
}
