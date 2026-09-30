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
	"fmt"
	"os"
	"sync"
	"time"
)

// PipelineRunner is the interface that the auto-trigger needs.
type PipelineRunner interface {
	Run(ctx context.Context, cfg PipelineConfig) *PipelineResult
}

// TriggerConfig holds configuration for the auto-trigger goroutine.
type TriggerConfig struct {
	Categories    []CategoryTrigger
	CheckInterval time.Duration // default 60s
}

// CategoryTrigger defines the trigger policy for one category.
type CategoryTrigger struct {
	Name        string
	MinTraces   int
	PipelineCfg PipelineConfig
}

// AutoTrigger monitors trace counts and auto-fires training pipelines.
type AutoTrigger struct {
	store    *Store
	pipeline PipelineRunner
	cfg      TriggerConfig
	running  map[string]bool // tracks which categories are currently training
	mu       sync.Mutex
	cancel   context.CancelFunc
}

// NewAutoTrigger constructs an auto-trigger instance.
func NewAutoTrigger(store *Store, pipeline PipelineRunner, cfg TriggerConfig) *AutoTrigger {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 60 * time.Second
	}
	return &AutoTrigger{
		store:    store,
		pipeline: pipeline,
		cfg:      cfg,
		running:  make(map[string]bool),
	}
}

// Start begins the background check loop.
func (t *AutoTrigger) Start(ctx context.Context) {
	childCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	go t.run(childCtx)
}

// Stop cancels the background loop.
func (t *AutoTrigger) Stop() {
	if t.cancel != nil {
		t.cancel()
	}
}

// IsRunning returns whether a category is currently training.
func (t *AutoTrigger) IsRunning(category string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running[category]
}

func (t *AutoTrigger) run(ctx context.Context) {
	ticker := time.NewTicker(t.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.checkAndFire(ctx)
		}
	}
}

func (t *AutoTrigger) checkAndFire(ctx context.Context) {
	for _, cat := range t.cfg.Categories {
		if t.IsRunning(cat.Name) {
			continue
		}

		count, err := t.store.CountByCategory(cat.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[training] auto-trigger: count failed for %s: %v\n", cat.Name, err)
			continue
		}

		if count >= cat.MinTraces {
			t.mu.Lock()
			t.running[cat.Name] = true
			t.mu.Unlock()

			go func(catName string, cfg PipelineConfig) {
				defer func() {
					t.mu.Lock()
					delete(t.running, catName)
					t.mu.Unlock()
				}()

				fmt.Fprintf(os.Stderr, "[training] auto-trigger: firing pipeline for %s (%d traces)\n", catName, count)
				result := t.pipeline.Run(ctx, cfg)
				if result.Error != nil {
					fmt.Fprintf(os.Stderr, "[training] auto-trigger: pipeline failed for %s: %v\n", catName, result.Error)
				} else {
					fmt.Fprintf(os.Stderr, "[training] auto-trigger: pipeline completed for %s (state=%s)\n", catName, result.State)
				}
			}(cat.Name, cat.PipelineCfg)
		}
	}
}
