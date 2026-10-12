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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0097 (TS r5): a loop of 17,500 short processes in a sandbox with the
// kernel feed gave 621 sandbox.process_tree records; the rest were held
// back by the record rate with one log line a minute and nothing in
// sandbox ps. The tree keeps every process, and the list counts the
// records not sent.
func TestProcessRecordsOverTheRateAreCounted(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, id := kernelBox(t, "ratebox", &sample)
	ctx := context.Background()
	at := time.Now().Add(-time.Second)
	const n = sandboxapi.ProcessRecordBurst + 100
	for i := range n {
		e.m.observeKernelFrame(ctx, b, execFrame(id, fmt.Sprintf("marker-%d", i), "", 20000+i, 0, "/bin/true", "/bin/true dccert-burst-marker", at))
	}
	list, err := e.m.Processes(ctx, "ratebox")
	if err != nil {
		t.Fatal(err)
	}
	// The gate refills at the rate while the frames arrive: a few more pass.
	sent := len(processRecords(e, "ratebox"))
	if sent < sandboxapi.ProcessRecordBurst || list.RecordsNotSent == 0 || int64(sent)+list.RecordsNotSent != n {
		t.Fatalf("sent %d, not sent %d of %d", sent, list.RecordsNotSent, n)
	}
}
