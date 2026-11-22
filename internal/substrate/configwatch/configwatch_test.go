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

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// loadAllow decodes "a,b" into a substrate allow list; "bad" does not load.
func loadAllow(_ string, raw []byte) (*config.Config, error) {
	s := strings.TrimSpace(string(raw))
	if s == "bad" {
		return nil, errors.New("does not load")
	}
	c := &config.Config{}
	c.Substrate.Enabled = s != "off"
	c.Substrate.Egress.Allow = strings.Split(s, ",")
	return c, nil
}

func newFileWatcher(t *testing.T, content string) (*Watcher, string, *fakeClock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	boot, _ := loadAllow(path, []byte(content))
	w, err := Start(path, boot)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2026, 11, 14, 17, 0, 0, 0, time.UTC)}
	w.Load, w.Now = loadAllow, clk.now
	return w, path, clk
}

func allow(c *config.Config) string { return strings.Join(c.Substrate.Egress.Allow, ",") }

func TestFileChangeIsSeenAfterTheInterval(t *testing.T) {
	w, path, clk := newFileWatcher(t, "a,b")
	if ch := w.Refresh(context.Background()); ch.Changed || allow(ch.Config) != "a,b" || ch.Digest != Digest([]byte("a,b")) {
		t.Fatalf("first read: %+v", ch)
	}
	if err := os.WriteFile(path, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(DefaultInterval - time.Millisecond)
	if ch := w.Refresh(context.Background()); ch.Changed {
		t.Fatal("read again inside the interval")
	}
	clk.t = clk.t.Add(time.Millisecond)
	ch := w.Refresh(context.Background())
	if !ch.Changed || allow(ch.Config) != "a" || ch.Previous != Digest([]byte("a,b")) || ch.Digest != Digest([]byte("a")) {
		t.Fatalf("change: %+v", ch)
	}
	if c, d := w.Current(); allow(c) != "a" || d != ch.Digest {
		t.Fatalf("Current = %v %s", allow(c), d)
	}
}

func TestBadSourceIsRefusedOnceAndLastGoodStays(t *testing.T) {
	w, path, clk := newFileWatcher(t, "a,b")
	for _, src := range []string{"bad", "off"} {
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		clk.t = clk.t.Add(DefaultInterval)
		ch := w.Refresh(context.Background())
		if ch.Changed || ch.Refused == nil || allow(ch.Config) != "a,b" {
			t.Fatalf("%s: %+v", src, ch)
		}
		clk.t = clk.t.Add(DefaultInterval)
		if ch := w.Refresh(context.Background()); ch.Refused != nil || ch.Changed {
			t.Fatalf("%s refused twice: %+v", src, ch)
		}
	}
	// Back to the source in force: no change, and a later bad source is
	// reported again.
	if err := os.WriteFile(path, []byte("a,b"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); ch.Changed || ch.Refused != nil {
		t.Fatalf("restored: %+v", ch)
	}
	if err := os.WriteFile(path, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); ch.Refused == nil {
		t.Fatal("a new bad edit was not reported")
	}
}

func TestConfigMapWinsAndFileIsTheFallback(t *testing.T) {
	w, path, clk := newFileWatcher(t, "a,b")
	var cm []byte
	var found bool
	ferr := errors.New("forbidden")
	w.Fetch = func(context.Context) ([]byte, bool, error) { return cm, found, ferr }
	// The API has never answered (no RBAC yet): the mounted file is the
	// source, with one warning.
	if err := os.WriteFile(path, []byte("a,c"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(DefaultInterval)
	ch := w.Refresh(context.Background())
	if !ch.Changed || allow(ch.Config) != "a,c" || !strings.Contains(ch.FetchWarning, "forbidden") {
		t.Fatalf("fallback before the API answered: %+v", ch)
	}
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); ch.FetchWarning != "" {
		t.Fatal("the same API failure warned twice")
	}
	// The API answers: its source wins over the file.
	ferr, cm, found = nil, []byte("a"), true
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); !ch.Changed || allow(ch.Config) != "a" || ch.FetchWarning != "" {
		t.Fatalf("ConfigMap edit: %+v", ch)
	}
	// From now on a failed read keeps the config in force (GAP-0293).
	ferr = errors.New("forbidden")
	clk.t = clk.t.Add(DefaultInterval)
	if ch := w.Refresh(context.Background()); ch.Changed || allow(ch.Config) != "a" || !strings.Contains(ch.FetchWarning, "stays") {
		t.Fatalf("API failure after it answered: %+v", ch)
	}
}

func TestDefaultLoaderIsTheStrictReloadLoader(t *testing.T) {
	w := New(filepath.Join(t.TempDir(), "config.yaml"), &config.Config{}, []byte("x"))
	w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte("not: [valid"), true, nil }
	ch := w.Refresh(context.Background())
	if ch.Changed || ch.Refused == nil {
		t.Fatalf("an invalid source loaded: %+v", ch)
	}
}
