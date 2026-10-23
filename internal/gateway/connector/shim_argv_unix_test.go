// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRenderedShimsPostExecutableAndExactArgv(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skipf("jq is required to exercise rendered shims: %v", err)
	}
	gateway, addr := newHookArgvGateway(t)
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteShimScriptsWithToken(shimDir, addr, "scoped-shim-token"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	for _, name := range shimBinaries {
		realTool := filepath.Join(binDir, name)
		body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DEFENSECLAW_SHIM_CAPTURE\"\n"
		if err := os.WriteFile(realTool, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	inputArgv := []string{"--leading-dash", "argument with spaces", "https://collector.invalid/upload"}
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			gateway.take()
			capturePath := filepath.Join(root, name+".args")
			command := exec.Command(systemBashForTest(t), append([]string{filepath.Join(shimDir, name)}, inputArgv...)...)
			command.Env = append(sanitizedTestEnv(), "HOME="+home,
				"PATH="+shimDir+":"+binDir+":/usr/local/bin:/usr/bin:/bin",
				"DEFENSECLAW_SHIM_CAPTURE="+capturePath)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("shim did not start its real tool: %v\n%s", err, output)
			}
			calls := gateway.take()
			if len(calls) != 1 || calls[0].path != "/api/v1/inspect/tool" || calls[0].authorization != "Bearer scoped-shim-token" {
				t.Fatalf("gateway inspection requests = %+v, want one authenticated request", calls)
			}
			var request struct {
				Tool string                     `json:"tool"`
				Args map[string]json.RawMessage `json:"args"`
			}
			if err := json.Unmarshal([]byte(calls[0].body), &request); err != nil {
				t.Fatal(err)
			}
			if request.Tool != name || len(request.Args) != 1 {
				t.Fatalf("inspection tool=%q args=%v, want %s and only argv", request.Tool, request.Args, name)
			}
			var gotArgv []string
			if err := json.Unmarshal(request.Args["argv"], &gotArgv); err != nil {
				t.Fatal(err)
			}
			wantArgv := append([]string{name}, inputArgv...)
			if !slices.Equal(gotArgv, wantArgv) {
				t.Fatalf("inspection argv = %#v, want %#v", gotArgv, wantArgv)
			}
			raw, err := os.ReadFile(capturePath)
			if err != nil {
				t.Fatalf("real tool did not run: %v", err)
			}
			realArgv := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			if !slices.Equal(realArgv, inputArgv) {
				t.Fatalf("real tool argv = %#v, want %#v", realArgv, inputArgv)
			}
		})
	}
}
