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

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// recordHandEdit records config bytes the watcher applied but no writer
// recorded (an edit in a text editor) as the next config_generation, with
// actor hand-edit:<os-user> (spec section 5). Only on a per-user (OSS)
// install: a managed deployment's lifecycle reverts an in-place edit
// instead. It takes the writer lock, so a CLI or TUI write in progress
// records its own generation first, and it records nothing when the file
// changed again since raw was read (the next reload handles that).
func recordHandEdit(ctx context.Context, cfg *config.Config, path string, raw []byte) {
	if cfg == nil || len(raw) == 0 || strings.TrimSpace(path) == "" ||
		managed.IsManagedEnterprise(cfg.DeploymentMode) || cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return
	}
	if _, recorded := readConfigGeneration(path, raw); recorded {
		return
	}
	sum := configwrite.SHA256Hex(raw)
	_, err := configwrite.Locked(ctx, path, configwrite.Options{
		Actor:  configwrite.CurrentActor(configwrite.ActorPrefixHandEdit),
		Reason: "config.yaml edited outside the config writer",
	}, func() (bool, error) {
		current, err := os.ReadFile(path)
		if err != nil || configwrite.SHA256Hex(current) != sum {
			return false, err
		}
		state, err := configwrite.ReadGenerationState(path)
		return err != nil || !strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), sum), nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[config] could not record the hand edit of %s: %v\n", path, err)
	}
}
