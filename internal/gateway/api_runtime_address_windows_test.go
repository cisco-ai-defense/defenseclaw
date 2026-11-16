// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The CLI sends a saved listener edit's audit fact to the running listener
// only when gateway-api.json has a protected owner-only DACL; under the
// per-user data dir, whose private ACEs are inheritable, a written record
// inherited them and the CLI refused it (GAP-2322).
func TestRuntimeAPIAddressRecordHasAProtectedDACLUnderTheDataDir(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = testenv.PrivateTempDir(t)
	api := &APIServer{scannerCfg: cfg}
	path := filepath.Join(cfg.DataDir, "gateway-api.json")
	for round := 0; round < 2; round++ { // the first write and a replacement
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		err = api.recordRuntimeAPIAddress(listener)
		_ = listener.Close()
		if err != nil {
			t.Fatal(err)
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("write %d: gateway-api.json inherits its DACL from the data dir; the CLI refuses such a record", round+1)
		}
		testenv.AssertPrivateFile(t, path)
		if err := safefile.ValidatePrivateFile(path); err != nil {
			t.Fatalf("write %d: %v", round+1, err)
		}
	}
}
