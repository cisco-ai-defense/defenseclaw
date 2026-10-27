// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// recordRuntimeAPIAddress publishes delivery evidence for this process. Saved
// listener edits apply on restart; CLI audit facts must still reach the live
// listener even when several edits cancel within one watcher debounce.
func (a *APIServer) recordRuntimeAPIAddress(listener net.Listener) error {
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil || cfg.DataDir == "" || cfg.SecureClientIntegration() || cfg.StandaloneEnterprise() {
		return nil
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	host := address.IP
	if host.IsUnspecified() {
		if host.To4() != nil {
			host = net.IPv4(127, 0, 0, 1)
		} else {
			host = net.IPv6loopback
		}
	}
	if !host.IsLoopback() {
		return nil
	}
	body, err := json.Marshal(struct {
		PID  int    `json:"pid"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}{os.Getpid(), host.String(), address.Port})
	if err != nil {
		return err
	}
	return configwrite.WriteFileDurable(filepath.Join(cfg.DataDir, "gateway-api.json"), body, 0o600)
}
