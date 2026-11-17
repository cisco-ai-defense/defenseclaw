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
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// configMapMount lays out path the way the kubelet mounts a ConfigMap key:
// config.yaml is a symlink to ..data/config.yaml, ..data a symlink to a
// timestamped directory.
func configMapMount(t *testing.T, raw string) string {
	t.Helper()
	dir := t.TempDir()
	ts := filepath.Join(dir, "..2026_11_17_00_00_00.000000001")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, ConfigMapKey), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ConfigMapKey)
	if err := os.Symlink(filepath.Join("..data", ConfigMapKey), path); err != nil {
		t.Fatal(err)
	}
	return path
}

func ossSource(dataDir, extra string) string {
	return "config_version: 9\ndata_dir: " + dataDir + "\n" + extra +
		"substrate:\n  enabled: true\n  identity:\n    issuer: https://idp.ate-system.svc\n    audience: defenseclaw\n" +
		"    token_lifetime_seconds: 300\n  egress:\n    allow:\n    - github.com\n"
}

// bootWatcher is a watcher on an OSS ConfigMap mount whose API read returns
// whatever *next holds, with a clock that moves past the read interval on
// every Refresh.
func bootWatcher(t *testing.T, next *string) *Watcher {
	t.Helper()
	dataDir := t.TempDir()
	raw := ossSource(dataDir, "")
	path := configMapMount(t, raw)
	boot, err := config.LoadRuntimeV8CandidateFromBytes(path, []byte(raw))
	if err != nil {
		t.Fatalf("boot source does not load: %v", err)
	}
	w := New(path, boot, []byte(raw))
	*next = raw
	w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte(*next), true, nil }
	clock := time.Unix(1_800_000_000, 0)
	w.Now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	return w
}

// TestGAP0323DeploymentModeEditIsRefusedForTheModeChange: an edit of the
// ConfigMap that adds deployment_mode managed_enterprise is refused whole,
// and the refusal names the deployment_mode change, not the managed trust
// check of the symlinked mount.
func TestGAP0323DeploymentModeEditIsRefusedForTheModeChange(t *testing.T) {
	var next string
	w := bootWatcher(t, &next)
	_, before := w.Current()
	next = strings.Replace(next, "data_dir:", "deployment_mode: managed_enterprise\ndata_dir:", 1) +
		"  idle_suspend_after: 10m\n"
	ch := w.Refresh(context.Background())
	if ch.Refused == nil || ch.Changed {
		t.Fatalf("a deployment_mode edit was not refused: %+v", ch)
	}
	msg := ch.Refused.Error()
	if !strings.Contains(msg, "deployment_mode_change") || !strings.Contains(msg, "managed_enterprise") {
		t.Fatalf("refusal does not name the deployment_mode change: %v", msg)
	}
	if strings.Contains(msg, "trust check") || strings.Contains(msg, "symlink") {
		t.Fatalf("refusal names the mount instead of the mode change: %v", msg)
	}
	if _, d := w.Current(); d != before {
		t.Fatalf("config in force moved from %s to %s", before, d)
	}
}

// TestGAP0324UnknownTopLevelKeyIsRefusedLive: a key the schema does not
// declare is refused at the live reload as the boot loader refuses it, once,
// and the config in force stays; a valid edit after it still applies.
func TestGAP0324UnknownTopLevelKeyIsRefusedLive(t *testing.T) {
	var next string
	w := bootWatcher(t, &next)
	_, before := w.Current()
	for _, tc := range []struct{ name, edit string }{
		{"top-level", "smk17_unknown_key: 1\n"},
		{"misspelled section", "egres:\n  allow:\n  - pypi.org\n"},
		{"nested", "    alow:\n    - pypi.org\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next = ossSource(w.cur.DataDir, "") + tc.edit
			ch := w.Refresh(context.Background())
			if ch.Refused == nil || ch.Changed {
				t.Fatalf("an undeclared key was applied live: %+v", ch)
			}
			if !strings.Contains(ch.Refused.Error(), "declared field name") {
				t.Fatalf("refusal is not the schema's: %v", ch.Refused)
			}
			if _, d := w.Current(); d != before {
				t.Fatalf("config in force moved from %s to %s", before, d)
			}
			if again := w.Refresh(context.Background()); again.Refused != nil {
				t.Fatalf("the same refused source alerted twice: %v", again.Refused)
			}
		})
	}
	next = ossSource(w.cur.DataDir, "") + "  idle_suspend_after: 10m\n"
	ch := w.Refresh(context.Background())
	if ch.Refused != nil || !ch.Changed || ch.Config.Substrate.IdleSuspendAfter == "" {
		t.Fatalf("a valid edit after the refusals did not apply: %+v", ch)
	}
}

// TestGAP0324EveryChartConfigPassesTheReloadSchema: the schema pass the
// reload now runs accepts the config.yaml every chart golden renders, so a
// reload of a chart-rendered ConfigMap is not refused by it.
func TestGAP0324EveryChartConfigPassesTheReloadSchema(t *testing.T) {
	goldens, err := filepath.Glob("../../../deploy/helm/defenseclaw-substrate/tests/golden/*.yaml")
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no chart goldens: %v", err)
	}
	seen := 0
	for _, g := range goldens {
		raw, err := os.ReadFile(g)
		if err != nil {
			t.Fatal(err)
		}
		src := chartConfigYAML(raw)
		if src == nil {
			continue
		}
		seen++
		if err := config.ValidateV8SchemaBytes(ConfigMapKey, src); err != nil {
			t.Errorf("%s: chart config.yaml fails the reload schema pass: %v", filepath.Base(g), err)
		}
	}
	if seen < 5 {
		t.Fatalf("only %d chart goldens carry a config.yaml", seen)
	}
}

// chartConfigYAML is the first "config.yaml: |" block of a rendered chart.
func chartConfigYAML(golden []byte) []byte {
	var out bytes.Buffer
	in := false
	s := bufio.NewScanner(bytes.NewReader(golden))
	s.Buffer(make([]byte, 1<<20), 1<<24)
	for s.Scan() {
		line := s.Text()
		if !in {
			in = strings.TrimSpace(line) == "config.yaml: |"
			continue
		}
		if !strings.HasPrefix(line, "    ") && strings.TrimSpace(line) != "" {
			break
		}
		out.WriteString(strings.TrimPrefix(line, "    "))
		out.WriteByte('\n')
	}
	if out.Len() == 0 {
		return nil
	}
	return out.Bytes()
}
