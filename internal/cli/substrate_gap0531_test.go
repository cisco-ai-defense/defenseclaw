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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/bundle"
)

// GAP-0531 / GAP-0494 wiring: the pod's bundle store (admin listener and
// controller inbox, both built by newSubstrateBundleStore) decides the
// stage atespaces from the live config it is given, not the boot config.
func TestGAP0531BundleStoreIsWiredToTheLiveConfig(t *testing.T) {
	boot := &config.Config{}
	boot.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}}
	live := *boot
	live.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}, "ops": {"dc-ops"}}
	s := newSubstrateBundleStore(bundle.NewMemoryConfigMaps(), boot, func() *config.Config { return &live })
	if s.Live == nil || s.Live() != &live || s.Base != boot {
		t.Fatalf("store wiring: Live set %v, Base is boot %v", s.Live != nil, s.Base == boot)
	}
}

// GAP-0531: --allow-flagged without --apply is refused before anything is
// read (it was accepted silently on an empty pull).
func TestGAP0531AllowFlaggedNeedsApply(t *testing.T) {
	_, _, err := runSubstrate(t, newSubstratePullCmd(), "a1", "--allow-flagged")
	if cliusage.ExitCode(err) != 2 || !strings.Contains(err.Error(), "--allow-flagged goes with --apply") {
		t.Fatalf("err = %v (exit %d)", err, cliusage.ExitCode(err))
	}
}

// substrate-1 GAP-0489 (RV-T6A): pull's --exclude and --no-exclude say
// opposite things, refused before anything is read.
func TestGAP0489PullExcludeAndNoExcludeConflict(t *testing.T) {
	_, _, err := runSubstrate(t, newSubstratePullCmd(), "a1", "--exclude", "config/local.yaml", "--no-exclude")
	if cliusage.ExitCode(err) != 2 || !strings.Contains(err.Error(), "--no-exclude") {
		t.Fatalf("pull --exclude --no-exclude: %v (exit %d)", err, cliusage.ExitCode(err))
	}
}
