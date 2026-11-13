//go:build !windows

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

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// In the separate-user layout setup writes only the plugin credential,
// checks openclaw.json read-only and prints the block to merge; teardown
// removes the credential and leaves openclaw.json alone.
func TestOpenClawSeparateUserLayout(t *testing.T) {
	dir, opts, home := openClawExternalFixture(t)
	tokenDir := filepath.Join(filepath.Dir(home), "etc-dc")
	if err := os.MkdirAll(tokenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	grp, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	prevBroad := openClawBroadGroups
	openClawBroadGroups = map[string]bool{}
	t.Cleanup(func() { openClawBroadGroups = prevBroad })
	opts.OpenClawPluginAccount = me.Username
	opts.OpenClawPluginTokenGroup = grp.Name
	opts.OpenClawPluginTokenFile = filepath.Join(tokenDir, "openclaw-plugin.token")
	opts.HookAPIToken = strings.Repeat("a", 64)
	opts.HookAPITokenScoped = true
	configPath := filepath.Join(home, "openclaw.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewOpenClawConnector()
	err = c.Setup(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "merge this JSON into it") || !strings.Contains(err.Error(), dir) {
		t.Fatalf("Setup err = %v, want the block to merge", err)
	}
	if got := mustReadFileString(t, configPath); got != "{}\n" {
		t.Fatalf("separate-user setup wrote openclaw.json: %q", got)
	}
	block := openClawSeparateUserBlock(opts, c.pathsFor(opts))
	if err := os.WriteFile(configPath, []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup with the block merged: %v", err)
	}
	info, err := os.Stat(opts.OpenClawPluginTokenFile)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("token file: %v mode %v", err, info)
	}
	if got := strings.TrimSpace(mustReadFileString(t, opts.OpenClawPluginTokenFile)); got != opts.HookAPIToken {
		t.Fatalf("token file holds %q", got)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(block), &parsed); err != nil {
		t.Fatalf("printed block is not JSON: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil && !strings.Contains(err.Error(), "revoke") {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Stat(opts.OpenClawPluginTokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("teardown left the token file: %v", err)
	}
	if got := mustReadFileString(t, configPath); got != block {
		t.Fatal("teardown changed openclaw.json in the separate-user layout")
	}
}

// The credential folder must not let the plugin account swap the file.
func TestPublishOpenClawPluginTokenRefusesWritableFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := publishOpenClawPluginToken(filepath.Join(dir, "t"), "dcplugin", "", strings.Repeat("b", 64))
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v, want a writable-folder refusal", err)
	}
}

// The credential group must be named and must not be one every account is in.
func TestPublishOpenClawPluginTokenRefusesMissingOrBroadGroup(t *testing.T) {
	dir := t.TempDir()
	for _, group := range []string{"", "staff", "users"} {
		err := publishOpenClawPluginToken(filepath.Join(dir, "t"), group, "openclaw", strings.Repeat("c", 64))
		if err == nil || !strings.Contains(err.Error(), "plugin_token_group") {
			t.Errorf("group %q: err = %v, want a group refusal", group, err)
		}
	}
}
