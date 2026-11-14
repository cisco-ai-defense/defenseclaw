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
	"fmt"
	"time"
)

// StoreSchema is the leader store schema this build reads and writes. The
// chart's defenseclaw.cisco.com/store-schema annotation must equal it (a
// test checks), so the rollback check compares the same numbers.
const StoreSchema = 1

// StoreStateWriter is the part of the Kubernetes API RecordStoreState uses.
type StoreStateWriter interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error)
	UpdateConfigMap(ctx context.Context, cm *ConfigMap) error
	CreateConfigMap(ctx context.Context, cm *ConfigMap) error
}

// ErrStoreNewer is returned when the store was written by a newer schema
// than this build reads: the leader must not serve it (E25).
type ErrStoreNewer struct {
	Store, Ours int
	WrittenBy   string
}

func (e *ErrStoreNewer) Error() string {
	return fmt.Sprintf("the leader store is at schema %d (written by %s) and this build reads schema %d; restore the backup or upgrade",
		e.Store, orDefault(e.WrittenBy, "a newer release"), e.Ours)
}

// RecordStoreState writes the leader store's schema and the writing version
// into the store state ConfigMap, which the pre-upgrade and pre-rollback
// checks read (GAP-0081). It keeps a recorded backup name, and refuses a
// store newer than this build.
func RecordStoreState(ctx context.Context, kube StoreStateWriter, namespace, name, version string, now time.Time) (*StoreState, error) {
	cm, err := kube.GetConfigMap(ctx, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("store state: %w", err)
	}
	next := StoreState{SchemaVersion: StoreSchema, WrittenByVersion: version, UpdatedAt: now.UTC().Format(time.RFC3339)}
	if cm != nil {
		if cur, err := ParseStoreState(cm.Data); err == nil && cur != nil {
			if cur.SchemaVersion > StoreSchema {
				return cur, &ErrStoreNewer{Store: cur.SchemaVersion, Ours: StoreSchema, WrittenBy: cur.WrittenByVersion}
			}
			next.Backup = cur.Backup
			if cur.SchemaVersion == next.SchemaVersion && cur.WrittenByVersion == next.WrittenByVersion {
				return cur, nil // nothing changed
			}
		}
		cm.Data = next.Data()
		if err := kube.UpdateConfigMap(ctx, cm); err != nil {
			return nil, fmt.Errorf("store state: %w", err)
		}
		return &next, nil
	}
	if err := kube.CreateConfigMap(ctx, &ConfigMap{Namespace: namespace, Name: name, Data: next.Data()}); err != nil {
		return nil, fmt.Errorf("store state: %w", err)
	}
	return &next, nil
}
