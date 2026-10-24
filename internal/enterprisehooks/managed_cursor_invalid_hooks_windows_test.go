// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Loop round 2 review (Windows consolidation): C:\ProgramData\Cursor\hooks.json
// is Cursor's and the administrators' file. A repair that found it was not
// JSON replaced the whole file with a new guard file, so the administrator's
// bytes were lost. The release branch refused and kept them. Every repair
// path (repair of a damaged guard, adapter refresh at upgrade) now keeps
// such a file byte for byte, writes nothing else, and says what to do; once
// the administrator fixes or removes the file, the same repair rebuilds the
// guard. An empty file holds no bytes to lose and reads as an empty
// document, so a repair still registers the guard in it.
func TestWindowsCursorMachineGuardRepairKeepsAHooksFileThatIsNotJSON(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	invalid := []struct {
		name string
		data []byte
	}{
		{"not JSON", []byte("{ not json")},
		{"a save cut short", []byte(`{"version":1,"hooks":{"adminEvent":[{"type":"command","command":"admin-hook"}`)},
		{"byte order mark only", []byte("\xef\xbb\xbf")},
		{"two documents", []byte(`{"version":1,"hooks":{}}{"version":1,"hooks":{}}`)},
	}
	adapterDamage := []struct {
		name  string
		apply func(t *testing.T, paths windowsCursorPaths)
	}{
		{name: "adapter intact"},
		{name: "adapter missing", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Adapter); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "adapter changed", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := windowsManagedPolicyWriter(paths.Adapter, []byte("exit 0\r\n"), true); err != nil {
				t.Fatal(err)
			}
		}},
	}
	repairs := []struct {
		name string
		run  func(string) (bool, error)
	}{
		{"repair", RestoreWindowsCursorManagedAdapter},
		{"upgrade refresh", RefreshWindowsCursorManagedAdapter},
	}
	type files struct {
		hooks, adapter, state, receipt []byte
		adapterExists                  bool
	}
	read := func(t *testing.T, paths windowsCursorPaths) files {
		t.Helper()
		var result files
		for path, target := range map[string]*[]byte{paths.Hooks: &result.hooks, paths.Adapter: &result.adapter, paths.State: &result.state, paths.Receipt: &result.receipt} {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if path == paths.Adapter {
				result.adapterExists = err == nil
			}
			*target = data
		}
		return result
	}
	for _, enrolled := range []bool{false, true} {
		for _, content := range invalid {
			for _, adapter := range adapterDamage {
				for _, repair := range repairs {
					name := map[bool]string{false: "empty", true: "Alice"}[enrolled] + "/" + content.name + "/" + adapter.name + "/" + repair.name
					t.Run(name, func(t *testing.T) {
						paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
						if err := windowsManagedPolicyWriter(paths.Hooks, content.data, true); err != nil {
							t.Fatal(err)
						}
						if adapter.apply != nil {
							adapter.apply(t, paths)
						}
						before := read(t, paths)
						restored, err := repair.run(hook)
						if err == nil || restored {
							t.Fatalf("%s over a hooks.json that is not JSON: restored=%t err=%v", repair.name, restored, err)
						}
						if !strings.Contains(err.Error(), "is not JSON") || !strings.Contains(err.Error(), "fix the file or remove it") {
							t.Fatalf("the refusal does not say what to do: %v", err)
						}
						after := read(t, paths)
						if !bytes.Equal(after.hooks, content.data) {
							t.Fatalf("the repair replaced the administrator's hooks.json: %q, want %q", after.hooks, content.data)
						}
						if after.adapterExists != before.adapterExists || !bytes.Equal(after.adapter, before.adapter) ||
							!bytes.Equal(after.state, before.state) || !bytes.Equal(after.receipt, before.receipt) {
							t.Fatal("a refused repair wrote a guard file")
						}

						// The administrator removes the file: the same repair
						// now rebuilds the whole guard.
						if err := os.Remove(paths.Hooks); err != nil {
							t.Fatal(err)
						}
						if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
							t.Fatalf("repair after the administrator removed hooks.json: restored=%t err=%v", restored, err)
						}
						rebuilt, err := os.ReadFile(paths.Hooks)
						if err != nil {
							t.Fatal(err)
						}
						if err := connector.VerifyWindowsCursorEnterpriseHooks(rebuilt, paths.Adapter, "closed"); err != nil {
							t.Fatalf("rebuilt registration is not the closed guard: %v", err)
						}
						if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
							t.Fatalf("rebuilt guard: active=%t err=%v", active, err)
						}
					})
				}
			}
		}
	}
}
