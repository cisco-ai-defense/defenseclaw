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

package training

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockPipeline is a test double that satisfies the Pipeline interface
type mockPipeline struct {
	runFunc func(ctx context.Context, cfg PipelineConfig) error
}

func (m *mockPipeline) Run(ctx context.Context, cfg PipelineConfig) *PipelineResult {
	if m.runFunc != nil {
		m.runFunc(ctx, cfg)
	}
	return &PipelineResult{State: StatePromoted}
}

func TestAutoTrigger_DoesNotFireBelowThreshold(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "training-trigger-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Insert 10 traces for category "test"
	for i := 0; i < 10; i++ {
		err := store.CaptureTrace(TraceEntry{
			Category:  "test",
			Prompt:    "test prompt",
			Response:  "test response",
			ModelUsed: "test-model",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	pipelineRan := false
	mockPipeline := &mockPipeline{
		runFunc: func(ctx context.Context, cfg PipelineConfig) error {
			pipelineRan = true
			return nil
		},
	}

	trigger := NewAutoTrigger(store, mockPipeline, TriggerConfig{
		Categories: []CategoryTrigger{
			{
				Name:      "test",
				MinTraces: 100, // threshold NOT met
				PipelineCfg: PipelineConfig{
					Category:  "test",
					BaseModel: "test-model",
				},
			},
		},
		CheckInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	trigger.Start(ctx)
	<-ctx.Done()
	trigger.Stop()

	if pipelineRan {
		t.Error("pipeline should not have run (below threshold)")
	}
}

func TestAutoTrigger_IsRunning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "training-trigger-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mp := &mockPipeline{}

	trigger := NewAutoTrigger(store, mp, TriggerConfig{
		Categories: []CategoryTrigger{
			{
				Name:      "test",
				MinTraces: 1,
			},
		},
		CheckInterval: 100 * time.Millisecond,
	})

	if trigger.IsRunning("test") {
		t.Error("should not be running initially")
	}

	trigger.mu.Lock()
	trigger.running["test"] = true
	trigger.mu.Unlock()

	if !trigger.IsRunning("test") {
		t.Error("should be running after manual set")
	}

	trigger.mu.Lock()
	delete(trigger.running, "test")
	trigger.mu.Unlock()

	if trigger.IsRunning("test") {
		t.Error("should not be running after delete")
	}
}
