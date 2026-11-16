// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// GAP-2446: ensure --config on a Mac whose etc folder carries the uchg flag
// and whose config.yaml a standard user wrote through a macOS ACL entry.
// The run clears the flag (and says so), removes the entry and puts a new
// file in place of the ACL-written one. A flag that cannot be cleared
// stops the run with the folder and the chflags command that clears it.
func TestEnsureConfigClearsAFlagOfTheConfigFolderAndReplacesTheACLWrittenFile(t *testing.T) {
	for _, clearFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleared", true: "clear-fails"}[clearFails], func(t *testing.T) {
			h := newTestHost(t, "darwin")
			pushed := machinePolicyConfig(t, h, "claudecode")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: pushed}))
			installed := h.read(h.env.Layout.ConfigPath)
			config := h.env.P(h.env.Layout.ConfigPath)
			etc := h.env.P(h.env.Layout.ConfigDir)
			edited := strings.Replace(installed, "mode: observe", "mode: action", 1)
			if edited == installed {
				t.Fatal("the edit changes nothing")
			}
			if err := os.WriteFile(config, []byte(edited), 0o640); err != nil {
				t.Fatal(err)
			}
			h.runner.acls = map[string][]string{config: {"user:standard allow write"}}
			h.runner.replies = map[string]fakeReply{}
			flagged := map[string]bool{etc: true}
			var asked []string
			h.env.clearDirFlags = func(path string) (string, error) {
				asked = append(asked, path)
				if !flagged[path] {
					return "", nil
				}
				if clearFails {
					return "uchg", errors.New("operation not permitted")
				}
				delete(flagged, path)
				return "uchg", nil
			}
			result := h.run(Options{Action: ActionEnsure, ConfigFile: pushed})
			if !strings.Contains(strings.Join(asked, "\n")+"\n", etc+"\n") {
				t.Fatalf("the flags of the config folder were not read: %v", asked)
			}
			if clearFails {
				requireError(t, result, codeApply)
				want := "chflags nouchg " + etc
				if !strings.Contains(result.Errors[0].Message, want) || !strings.Contains(result.Errors[0].Message, "uchg flag") {
					t.Fatalf("error %q does not name the flag and %q", result.Errors[0].Message, want)
				}
				return
			}
			requireOK(t, result)
			if got := h.read(h.env.Layout.ConfigPath); got == edited {
				t.Fatal("the config.yaml written through the ACL entry stayed in place")
			}
			note := "cleared the macOS uchg flag of " + etc
			if !strings.Contains(strings.Join(result.Changes, "\n"), note) {
				t.Fatalf("changes %q do not say %q", result.Changes, note)
			}
			if record, _ := h.env.loadDeployment(); record.ConfigSHA256 == sha256Bytes([]byte(edited)) {
				t.Fatal("the ACL-written config was applied")
			}
		})
	}
}
