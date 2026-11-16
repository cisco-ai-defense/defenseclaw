// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestStatusReportsWhetherDaemonActuallyOwnsSandboxListeners(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.m.opts.Listeners = func() error { return errors.New("ingress port is held by another account") }
	st, err := e.m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Available || !strings.Contains(st.Reason, "another account") {
		t.Fatalf("unbound listener was advertised as available: %+v", st)
	}
	e.m.opts.Listeners = func() error { return nil }
	st, err = e.m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available {
		t.Fatalf("bound listeners were not reported available: %+v", st)
	}
}
