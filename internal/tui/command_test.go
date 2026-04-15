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

package tui

import (
	"strings"
	"testing"
)

func TestBuildRegistry(t *testing.T) {
	registry := BuildRegistry()

	if len(registry) == 0 {
		t.Fatal("registry is empty")
	}

	t.Run("minimum_command_count", func(t *testing.T) {
		if len(registry) < 50 {
			t.Errorf("expected at least 50 commands, got %d", len(registry))
		}
	})

	t.Run("all_entries_have_required_fields", func(t *testing.T) {
		for _, entry := range registry {
			if entry.TUIName == "" {
				t.Error("entry has empty TUIName")
			}
			if entry.CLIBinary == "" {
				t.Errorf("entry %q has empty CLIBinary", entry.TUIName)
			}
			if len(entry.CLIArgs) == 0 {
				t.Errorf("entry %q has empty CLIArgs", entry.TUIName)
			}
			if entry.Description == "" {
				t.Errorf("entry %q has empty Description", entry.TUIName)
			}
			if entry.Category == "" {
				t.Errorf("entry %q has empty Category", entry.TUIName)
			}
		}
	})

	t.Run("cli_binary_is_known", func(t *testing.T) {
		for _, entry := range registry {
			if entry.CLIBinary != "defenseclaw" && entry.CLIBinary != "defenseclaw-gateway" {
				t.Errorf("entry %q has unexpected CLIBinary %q", entry.TUIName, entry.CLIBinary)
			}
		}
	})

	t.Run("needs_arg_implies_arg_hint", func(t *testing.T) {
		for _, entry := range registry {
			if entry.NeedsArg && entry.ArgHint == "" {
				t.Errorf("entry %q has NeedsArg=true but empty ArgHint", entry.TUIName)
			}
		}
	})

	t.Run("no_duplicate_tui_names", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, entry := range registry {
			if seen[entry.TUIName] {
				t.Errorf("duplicate TUIName: %q", entry.TUIName)
			}
			seen[entry.TUIName] = true
		}
	})

	t.Run("expected_categories", func(t *testing.T) {
		cats := map[string]bool{
			"setup": false, "scan": false, "enforce": false,
			"daemon": false, "info": false, "policy": false,
			"sandbox": false, "install": false, "other": false,
		}
		for _, entry := range registry {
			cats[entry.Category] = true
		}
		for cat, found := range cats {
			if !found {
				t.Errorf("expected category %q not found in registry", cat)
			}
		}
	})
}

func TestMatchCommand(t *testing.T) {
	registry := BuildRegistry()

	tests := []struct {
		name      string
		input     string
		wantTUI   string
		wantExtra string
		wantNil   bool
	}{
		{
			name:    "empty_input",
			input:   "",
			wantNil: true,
		},
		{
			name:    "no_match",
			input:   "nonexistent-command",
			wantNil: true,
		},
		{
			name:      "exact_match_no_arg",
			input:     "init",
			wantTUI:   "init",
			wantExtra: "",
		},
		{
			name:      "exact_match_no_arg_status",
			input:     "status",
			wantTUI:   "status",
			wantExtra: "",
		},
		{
			name:      "match_with_extra_arg",
			input:     "scan skill my-agent",
			wantTUI:   "scan skill",
			wantExtra: "my-agent",
		},
		{
			name:      "match_mcp_scan_with_url",
			input:     "scan mcp https://example.com/mcp",
			wantTUI:   "scan mcp",
			wantExtra: "https://example.com/mcp",
		},
		{
			name:      "longer_prefix_wins",
			input:     "scan skill --all",
			wantTUI:   "scan skill --all",
			wantExtra: "",
		},
		{
			name:      "block_skill_with_target",
			input:     "block skill evil-skill",
			wantTUI:   "block skill",
			wantExtra: "evil-skill",
		},
		{
			name:      "daemon_start",
			input:     "start",
			wantTUI:   "start",
			wantExtra: "",
		},
		{
			name:      "daemon_restart",
			input:     "restart",
			wantTUI:   "restart",
			wantExtra: "",
		},
		{
			name:      "policy_list",
			input:     "policy list",
			wantTUI:   "policy list",
			wantExtra: "",
		},
		{
			name:      "doctor",
			input:     "doctor",
			wantTUI:   "doctor",
			wantExtra: "",
		},
		{
			name:      "sandbox_exec_with_arg",
			input:     "sandbox exec ls -la",
			wantTUI:   "sandbox exec",
			wantExtra: "ls -la",
		},
		{
			name:      "whitespace_trimmed",
			input:     "  status  ",
			wantTUI:   "status",
			wantExtra: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, extra := MatchCommand(tt.input, registry)

			if tt.wantNil {
				if entry != nil {
					t.Errorf("expected nil entry, got %q", entry.TUIName)
				}
				return
			}

			if entry == nil {
				t.Fatalf("expected entry for %q, got nil", tt.input)
			}
			if entry.TUIName != tt.wantTUI {
				t.Errorf("TUIName = %q, want %q", entry.TUIName, tt.wantTUI)
			}
			if extra != tt.wantExtra {
				t.Errorf("extra = %q, want %q", extra, tt.wantExtra)
			}
		})
	}
}

func TestMatchCommandCLIMapping(t *testing.T) {
	registry := BuildRegistry()

	tests := []struct {
		input     string
		wantBin   string
		wantArgs  []string
		wantExtra string
	}{
		{
			input:    "scan skill my-skill",
			wantBin:  "defenseclaw",
			wantArgs: []string{"skill", "scan"},
			wantExtra: "my-skill",
		},
		{
			input:    "block mcp https://mcp.example.com",
			wantBin:  "defenseclaw",
			wantArgs: []string{"mcp", "block"},
			wantExtra: "https://mcp.example.com",
		},
		{
			input:    "restart",
			wantBin:  "defenseclaw-gateway",
			wantArgs: []string{"restart"},
		},
		{
			input:    "policy evaluate",
			wantBin:  "defenseclaw-gateway",
			wantArgs: []string{"policy", "evaluate"},
		},
		{
			input:    "setup guardrail",
			wantBin:  "defenseclaw",
			wantArgs: []string{"setup", "guardrail"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			entry, extra := MatchCommand(tt.input, registry)
			if entry == nil {
				t.Fatalf("no match for %q", tt.input)
			}
			if entry.CLIBinary != tt.wantBin {
				t.Errorf("CLIBinary = %q, want %q", entry.CLIBinary, tt.wantBin)
			}
			if len(entry.CLIArgs) != len(tt.wantArgs) {
				t.Fatalf("CLIArgs = %v, want %v", entry.CLIArgs, tt.wantArgs)
			}
			for i, a := range entry.CLIArgs {
				if a != tt.wantArgs[i] {
					t.Errorf("CLIArgs[%d] = %q, want %q", i, a, tt.wantArgs[i])
				}
			}
			if extra != tt.wantExtra {
				t.Errorf("extra = %q, want %q", extra, tt.wantExtra)
			}
		})
	}
}

func TestCommandExecutorInitialState(t *testing.T) {
	executor := NewCommandExecutor()

	if executor.IsRunning() {
		t.Error("new executor should not be running")
	}
}

func TestCommandRegistryCategories(t *testing.T) {
	registry := BuildRegistry()

	catCount := make(map[string]int)
	for _, entry := range registry {
		catCount[entry.Category]++
	}

	t.Run("scan_commands_exist", func(t *testing.T) {
		if catCount["scan"] < 5 {
			t.Errorf("expected at least 5 scan commands, got %d", catCount["scan"])
		}
	})

	t.Run("enforce_commands_exist", func(t *testing.T) {
		if catCount["enforce"] < 10 {
			t.Errorf("expected at least 10 enforce commands, got %d", catCount["enforce"])
		}
	})

	t.Run("daemon_commands_exist", func(t *testing.T) {
		if catCount["daemon"] < 3 {
			t.Errorf("expected at least 3 daemon commands, got %d", catCount["daemon"])
		}
	})

	t.Run("policy_commands_exist", func(t *testing.T) {
		if catCount["policy"] < 5 {
			t.Errorf("expected at least 5 policy commands, got %d", catCount["policy"])
		}
	})
}

func TestCommandRegistryNoPrefixInTUINames(t *testing.T) {
	registry := BuildRegistry()

	for _, entry := range registry {
		if strings.HasPrefix(entry.TUIName, "defenseclaw ") {
			t.Errorf("TUIName %q should not have defenseclaw prefix", entry.TUIName)
		}
		if strings.HasPrefix(entry.TUIName, "defenseclaw-gateway ") {
			t.Errorf("TUIName %q should not have defenseclaw-gateway prefix", entry.TUIName)
		}
	}
}
