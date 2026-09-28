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

package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestUndoRunsToItsEndWhenTheCallerLeaves pins that an undo's restore is
// not cut short when the API request that started it goes away: the
// restore is a sequence of git steps on the user's folder.
func TestUndoRunsToItsEndWhenTheCallerLeaves(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "undoleave"})
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mid error
	e.ws.onUndo = func(c context.Context) {
		cancel() // the client disconnects while the restore runs
		mid = c.Err()
	}
	if _, err := e.m.Undo(ctx, sb.Name, sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if mid != nil {
		t.Fatalf("the restore ran on the request's context, which the client's leaving cancelled: %v", mid)
	}
}

// TestDeleteRunsToItsEndWhenTheCallerLeaves pins that a delete's cleanup
// is not cut short when the API request that started it goes away.
func TestDeleteRunsToItsEndWhenTheCallerLeaves(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "delleave"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mid error
	e.ws.onDeleteSnapshot = func(c context.Context) {
		cancel()
		mid = c.Err()
	}
	resp, err := e.m.Delete(ctx, sb.Name, sandboxapi.DeleteRequest{})
	if err != nil || !resp.Deleted {
		t.Fatalf("delete = %+v, %v", resp, err)
	}
	if mid != nil {
		t.Fatalf("the cleanup ran on the request's context, which the client's leaving cancelled: %v", mid)
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", "manager", sb.Name+".json")); !os.IsNotExist(err) {
		t.Fatalf("record left: %v", err)
	}
}
