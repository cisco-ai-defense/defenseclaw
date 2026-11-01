// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A MicroVM the OpenShell gateway's stop sync could not sync (a sign-out
// without linger, its guest sync broken) is named in the next daemon's
// feed as stop_unflushed, at the time of the stop, not only in the
// gateway unit's journal (GAP-2081).
func TestAGatewayStopThatCouldNotSyncReachesTheFeed(t *testing.T) {
	e := newEnv(t, nil)
	at := time.Date(2026, 10, 26, 21, 40, 0, 0, time.UTC)
	if err := RecordUnsyncedStops(e.dataDir, []string{"f-a", "../not-a-name"}, at); err != nil {
		t.Fatal(err)
	}
	_ = e.m.Reconcile(context.Background())
	got := e.events("f-a", sandboxapi.ActivityLifecycle, "stop_unflushed")
	if len(got) != 1 || !got[0].Time.Equal(at) || !strings.Contains(got[0].Message, "may come back empty") {
		t.Fatalf("feed %+v", e.m.ActivitySince(0, ""))
	}
	if n := len(e.events("", "", "stop_unflushed")); n != 1 {
		t.Fatalf("%d stop_unflushed events, want 1", n)
	}
	if _, err := os.Stat(unsyncedStopsPath(e.dataDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the record stays after the feed took it: %v", err)
	}
	_ = e.m.Reconcile(context.Background())
	if n := len(e.events("", "", "stop_unflushed")); n != 1 {
		t.Fatalf("the stop was told %d times", n)
	}
}
