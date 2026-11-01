// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRuntimeAPIAddressNamesTheBoundListener(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	api := &APIServer{scannerCfg: cfg}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := api.recordRuntimeAPIAddress(listener); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "gateway-api.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		PID  int
		Host string
		Port int
	}
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	if record.PID != os.Getpid() || record.Host != "127.0.0.1" || record.Port != listener.Addr().(*net.TCPAddr).Port {
		t.Fatalf("runtime listener=%+v, actual=%s", record, listener.Addr())
	}
	if info, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("descriptor custody=%v %v", info, err)
	}
}
