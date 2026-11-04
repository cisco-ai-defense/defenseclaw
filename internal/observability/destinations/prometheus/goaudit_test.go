// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"testing"
	"time"
)

var goauditHealthCalls chan struct{}

type goauditHealthObserver struct{}

func (*goauditHealthObserver) Observe(HealthTransition) {
	goauditHealthCalls <- struct{}{}
}

func TestBoundedObserverSkipsTypedNilTarget(t *testing.T) {
	goauditHealthCalls = make(chan struct{}, 2)
	var missing *goauditHealthObserver
	newBoundedObserver(missing).observe(HealthTransition{})
	select {
	case <-goauditHealthCalls:
		t.Fatal("nil observer was invoked")
	case <-time.After(300 * time.Millisecond):
	}
	newBoundedObserver(&goauditHealthObserver{}).observe(HealthTransition{})
	select {
	case <-goauditHealthCalls:
	case <-time.After(time.Second):
		t.Fatal("live observer was not invoked")
	}
}
