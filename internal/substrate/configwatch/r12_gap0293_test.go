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

package configwatch

// R12 review probes (not for commit).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An API read blip must not revert a tightening applied from the ConfigMap
// to the older mounted file (managed: the subPath file is the boot copy and
// never changes; OSS: the kubelet lags up to a minute).
func TestGAP0293APIBlipKeepsConfigMapTightening(t *testing.T) {
	w, _, clk := newFileWatcher(t, "a,b") // boot file allows a,b
	var cm []byte
	var ferr error
	w.Fetch = func(context.Context) ([]byte, bool, error) { return cm, ferr == nil, ferr }
	cm = []byte("a") // admin removes b in the ConfigMap
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); !ch.Changed || allow(ch.Config) != "a" {
		t.Fatalf("tightening: %+v", ch)
	}
	ferr = errors.New("dial tcp: i/o timeout") // one failed API read
	clk.t = clk.t.Add(DefaultInterval)
	ch := w.Refresh(context.Background())
	if got := allow(ch.Config); got != "a" {
		t.Fatalf("R12: one API read failure reverted the allow list to the stale mounted file: in force %q (Changed=%v)", got, ch.Changed)
	}
}

// Current() is on gateway request paths (live()); it must not wait for a
// slow ConfigMap read.
func TestGAP0296CurrentDoesNotWaitOnSlowFetch(t *testing.T) {
	w, _, clk := newFileWatcher(t, "a,b")
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	w.Fetch = func(ctx context.Context) ([]byte, bool, error) {
		once.Do(func() { close(started) })
		<-release
		return []byte("a,b"), true, nil
	}
	clk.t = clk.t.Add(DefaultInterval)
	go w.Refresh(context.Background())
	<-started
	done := make(chan struct{})
	go func() { w.Current(); close(done) }()
	select {
	case <-done:
		close(release)
	case <-time.After(500 * time.Millisecond):
		close(release)
		t.Fatal("R12: Current() blocked while Refresh waited on the ConfigMap read (up to 5s per read when the API server is unreachable)")
	}
}

// TestGAP0293APIBlipNeverRevertsToTheFile: once the API has answered, a
// missing ConfigMap or key keeps the config in force too, even when the
// mounted file says something else; the API answering again applies.
func TestGAP0293APIBlipNeverRevertsToTheFile(t *testing.T) {
	w, path, clk := newFileWatcher(t, "a,b")
	var cm []byte
	found := true
	w.Fetch = func(context.Context) ([]byte, bool, error) { return cm, found, nil }
	cm = []byte("a")
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); allow(ch.Config) != "a" {
		t.Fatalf("tightening: %+v", ch)
	}
	if err := os.WriteFile(path, []byte("a,b,c"), 0o600); err != nil {
		t.Fatal(err)
	}
	found = false
	clk.t = clk.t.Add(DefaultInterval)
	ch := w.Refresh(context.Background())
	if allow(ch.Config) != "a" || ch.Changed || !strings.Contains(ch.FetchWarning, "stays") {
		t.Fatalf("missing ConfigMap after the API answered: %+v", ch)
	}
	found, cm = true, []byte("z")
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); !ch.Changed || allow(ch.Config) != "z" || ch.FetchWarning != "" {
		t.Fatalf("API back: %+v", ch)
	}
}

// TestGAP0294ManagedDowngradeIsRefusedLive: dropping managed_enterprise,
// changing the enterprise profile, or switching to managed in a ConfigMap
// edit is refused once and the config in force stays.
func TestGAP0294ManagedDowngradeIsRefusedLive(t *testing.T) {
	for _, tc := range []struct{ name, boot, next string }{
		{"downgrade", "managed_enterprise", ""},
		{"upgrade", "", "managed_enterprise"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boot := &config.Config{DeploymentMode: tc.boot}
			boot.Substrate.Enabled = true
			w := New(filepath.Join(t.TempDir(), "config.yaml"), boot, []byte("boot"))
			w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte("next"), true, nil }
			w.Load = func(string, []byte) (*config.Config, error) {
				c := &config.Config{DeploymentMode: tc.next}
				c.Substrate.Enabled = true
				c.Substrate.Egress.Allow = []string{"loosened.example"}
				return c, nil
			}
			ch := w.Refresh(context.Background())
			if ch.Changed || ch.Refused == nil || ch.Config != boot || !strings.Contains(ch.Refused.Error(), "restart") {
				t.Fatalf("a deployment_mode change applied live: %+v", ch)
			}
		})
	}
}
