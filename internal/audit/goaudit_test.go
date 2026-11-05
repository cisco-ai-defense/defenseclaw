// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

var goauditBusyCalls chan struct{}

type goauditBusyObserver struct{}

func (*goauditBusyObserver) RecordSQLiteBusyMetric(context.Context, string) error {
	goauditBusyCalls <- struct{}{}
	return nil
}

func TestReportSQLiteBusyDetachedSkipsTypedNilObserver(t *testing.T) {
	goauditBusyCalls = make(chan struct{}, 2)
	var missing *goauditBusyObserver
	reportSQLiteBusyDetached(context.Background(), missing, "audit_insert")
	select {
	case <-goauditBusyCalls:
		t.Fatal("nil observer was invoked")
	case <-time.After(300 * time.Millisecond):
	}
	reportSQLiteBusyDetached(context.Background(), &goauditBusyObserver{}, "audit_insert")
	select {
	case <-goauditBusyCalls:
	case <-time.After(time.Second):
		t.Fatal("live observer was not invoked")
	}
}
