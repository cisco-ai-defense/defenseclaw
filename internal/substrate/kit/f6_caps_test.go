// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0039 (fail closed past every cap): every plugin's skills folder is a
// root, past the old 64 too (the folder listing cap and its stand-ins bound
// what is listed), and a plugins folder the search could not finish stands
// in for the rest; refusing it puts the plugins out of reach.
func TestGAP0039EveryPluginSkillRootIsWatched(t *testing.T) {
	home := t.TempDir()
	plugins := filepath.Join(home, ".claude", "plugins")
	for i := 0; i < 70; i++ {
		_ = os.MkdirAll(filepath.Join(plugins, "cache", "m", fmt.Sprintf("p%02d", i), "1", "skills", "s"), 0o755)
	}
	// Not plugin install places: never searched.
	_ = os.MkdirAll(filepath.Join(plugins, "cache", "m", "p00", "1", "node_modules", "x", "skills"), 0o755)
	_ = os.MkdirAll(filepath.Join(plugins, ".git", "skills"), 0o755)
	roots, complete := pluginSkillRoots(plugins)
	if len(roots) != 70 || !complete {
		t.Fatalf("%d plugin skill roots (complete %v), want 70", len(roots), complete)
	}
}

func TestGAP0039PluginsStandInIsQuarantined(t *testing.T) {
	home := t.TempDir()
	plugins := filepath.Join(home, ".claude", "plugins")
	_ = os.MkdirAll(filepath.Join(plugins, "cache", "m", "p", "1", "skills", "s"), 0o755)
	// The stand-in the kit lists when the search stops (pluginSkillRoots
	// complete=false): skillRoots adds the plugins folder itself.
	f := &Facts{}
	listed, _ := collectSkills(f, []string{plugins}, nil, MaxAttachBytes, MaxAttachBytes)
	if listed[plugins] != skillRootStandIn || len(f.Skills) != 1 || !f.Skills[0].Over {
		t.Fatalf("listing %v %+v", listed, f.Skills)
	}
	answer, _ := json.Marshal(map[string]any{"substrate_quarantine": []map[string]string{{"path": plugins, "reason": "over the cap"}}})
	moved := applySkillAnswer(home, answer, listed, nil, time.Now())
	if len(moved) != 1 || moved[0] != plugins {
		t.Fatalf("moved %v", moved)
	}
	if _, err := os.Stat(plugins); !os.IsNotExist(err) {
		t.Fatalf("the plugins folder is still there: %v", err)
	}
}
