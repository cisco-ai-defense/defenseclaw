// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 1.0.4 review (loop round 2 of G-hooks-upg): `defenseclaw status` and
// `doctor` read hooks/.hookcfg to report the native Windows hook's fail mode,
// and disagreed with the hook on a gateway_addr that is not a string, a peer
// entry that is not a string, and a connector key in another case. Both
// readers now run these vectors (cli/tests/test_fail_mode_runtime.py
// test_windows_sidecar_report_matches_the_native_hook_contract).
func TestReadHookSidecarSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "windows_hook_sidecar_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name      string `json:"name"`
			Connector string `json:"connector"`
			Kind      string `json:"kind"`
			Body      string `json:"body"`
			BodyB64   string `json:"body_b64"`
			Mode      string `json:"mode"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			body := []byte(vector.Body)
			if vector.BodyB64 != "" {
				if body, err = base64.StdEncoding.DecodeString(vector.BodyB64); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			path := filepath.Join(dir, ".hookcfg")
			switch vector.Kind {
			case "missing":
			case "dir":
				err = os.Mkdir(path, 0o700)
			case "link":
				target := filepath.Join(dir, "target")
				if err = os.WriteFile(target, body, 0o600); err == nil {
					if linkErr := os.Symlink(target, path); linkErr != nil {
						t.Skipf("symlinks unavailable: %v", linkErr)
					}
				}
			case "oversize":
				err = os.WriteFile(path, append(body, bytes.Repeat([]byte(" "), 70<<10)...), 0o600)
			case "":
				err = os.WriteFile(path, body, 0o600)
			default:
				t.Fatalf("unknown kind %q", vector.Kind)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Status still reads the vector's mode (fail_mode.py); the
			// per-user native hook takes only the gateway address from any
			// sidecar and stays closed (sa-port-peer).
			for key := range readHookSidecar(path) {
				if key != "DEFENSECLAW_GATEWAY_ADDR" {
					t.Fatalf("the native hook read %q from the sidecar", key)
				}
			}
		})
	}
}
