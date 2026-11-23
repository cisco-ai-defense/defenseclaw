// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scanworker

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

func TestPodWorkerExitsOnStartupResetRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	w := &Worker{Dir: t.TempDir(), Pod: processutil.NewPodRunner(t.TempDir())}
	if err := w.Serve(ctx); err == nil {
		t.Fatal("pod worker served despite a refused initial reset")
	}
}
