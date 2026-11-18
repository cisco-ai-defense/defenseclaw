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

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
)

// substrate-1:GAP-0590. The gateway follower logged "config.yaml <digest> in
// force" as soon as its ConfigMap read saw an edit, while hooks and /llm
// switch only when the gateway's config manager reloads the mounted file:
// about a minute later on a directory mount, and never (until a restart) on
// a managed install's subPath mount. Its log now says the edit is seen and
// when the guardrail applies; the leader, and a gateway that reads only its
// file, keep "in force".
func TestGAP0590GatewayFollowerSaysWhenTheGuardrailApplies(t *testing.T) {
	boot := gap0276Config("", nil)
	configs := map[string]*config.Config{"boot": boot, "v2": gap0276Config("", func(c *config.Config) {
		c.Guardrail.DefaultProfile = "eng"
	})}
	follow := func(t *testing.T, role string, dirMount, api bool) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if dirMount {
			if err := os.Mkdir(filepath.Join(dir, "..2026_11_18_01_00_00.000000001"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("..2026_11_18_01_00_00.000000001", filepath.Join(dir, "..data")); err != nil {
				t.Fatal(err)
			}
		}
		raw, now := "boot", time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
		if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		w := configwatch.New(path, boot, []byte("boot"))
		if api {
			w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte(raw), true, nil }
		}
		w.Load = func(_ string, b []byte) (*config.Config, error) {
			if c, ok := configs[string(b)]; ok {
				return c, nil
			}
			return nil, errors.New("does not load")
		}
		w.Now = func() time.Time { return now }
		var out bytes.Buffer
		f := newSubstrateFollower(w, role, &out, func(*config.Config) error { return nil })
		raw = "v2"
		if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		now = now.Add(configwatch.DefaultInterval)
		f.step(context.Background())
		return out.String()
	}
	digest := configwatch.Digest([]byte("v2"))

	dir := follow(t, "gateway", true, true)
	if strings.Contains(dir, "in force") || !strings.Contains(dir, digest+" seen") ||
		!strings.Contains(dir, "when the kubelet updates the mounted config.yaml") {
		t.Errorf("gateway on a directory mount: %q", dir)
	}
	sub := follow(t, "gateway", false, true)
	if strings.Contains(sub, "in force") || !strings.Contains(sub, digest+" seen") ||
		!strings.Contains(sub, "applies when this pod restarts") || !strings.Contains(sub, "rollout restart deploy/defenseclaw-gateway") {
		t.Errorf("gateway on a subPath mount: %q", sub)
	}
	if got := follow(t, "leader", false, true); !strings.Contains(got, digest+" in force") {
		t.Errorf("leader: %q", got)
	}
	if got := follow(t, "gateway", false, false); !strings.Contains(got, digest+" in force") {
		t.Errorf("gateway that reads its file only: %q", got)
	}
}
