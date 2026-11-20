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

package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (k *fakeKube) CreateConfigMap(_ context.Context, cm *ConfigMap) error {
	if k.cms[cm.Namespace+"/"+cm.Name] != nil {
		return errors.New("exists")
	}
	k.cms[cm.Namespace+"/"+cm.Name] = cm
	return nil
}

// GAP-0081: the leader records the store schema, so the rollback and
// upgrade checks have something to refuse with.
func TestRecordStoreStateFeedsTheRollbackCheck(t *testing.T) {
	ctx := context.Background()
	kube := newFakeKube()
	plan := testPlan()
	now := time.Date(2026, 11, 12, 23, 0, 0, 0, time.UTC)
	if _, err := RecordStoreState(ctx, kube, plan.Namespace, plan.StoreStateConfigMap, "1.0.10", now); err != nil {
		t.Fatal(err)
	}
	st, err := storeState(ctx, plan, kube)
	if err != nil || st == nil || st.SchemaVersion != StoreSchema || st.WrittenByVersion != "1.0.10" {
		t.Fatalf("state = %+v, %v", st, err)
	}
	// A store at a newer schema (written by a later release, with a backup)
	// refuses a rollback to this schema, and a leader of this build.
	kube.cms[plan.Namespace+"/"+plan.StoreStateConfigMap].Data = StoreState{SchemaVersion: StoreSchema + 1, Backup: "store-2026-11-12.tar", WrittenByVersion: "1.1.0"}.Data()
	plan.StoreSchema = StoreSchema
	if _, err := PreRollback(ctx, plan, kube); err == nil || !strings.Contains(err.Error(), "store-2026-11-12.tar") {
		t.Fatalf("rollback across a schema change allowed: %v", err)
	}
	var newer *ErrStoreNewer
	if _, err := RecordStoreState(ctx, kube, plan.Namespace, plan.StoreStateConfigMap, "1.0.10", now); !errors.As(err, &newer) {
		t.Fatalf("an older leader overwrote a newer store state: %v", err)
	}
	// Same schema, new version: the backup name is kept.
	kube.cms[plan.Namespace+"/"+plan.StoreStateConfigMap].Data = StoreState{SchemaVersion: StoreSchema, Backup: "b1", WrittenByVersion: "1.0.9"}.Data()
	st2, err := RecordStoreState(ctx, kube, plan.Namespace, plan.StoreStateConfigMap, "1.0.10", now)
	if err != nil || st2.Backup != "b1" || st2.WrittenByVersion != "1.0.10" {
		t.Fatalf("state = %+v, %v", st2, err)
	}
}

func TestStoreSchemaMatchesTheChart(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := `defenseclaw.cisco.com/store-schema: "` + strconv.Itoa(StoreSchema) + `"`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("Chart.yaml does not carry %s", want)
	}
}
