// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// homeGatewayPortHolder reads the socket table; tests replace it.
var homeGatewayPortHolder = FindPortHolder

// homeGatewayHolderIsThisAccount is holderIsThisAccount; tests replace it.
var homeGatewayHolderIsThisAccount = holderIsThisAccount

// HomeGatewayHoldsPort reports whether the socket table shows the listener on
// host:port held by this data directory's own gateway, a process other than
// the caller: the one its PID record names with a verified executable and
// start identity (defenseclaw-gateway start), or the one its private
// gateway-api.json names for that port (written by every gateway of this home
// once it binds, so a foreground gateway counts too). The holder must run as
// this account (holderIsThisAccount: the UID on Linux and macOS, the token
// user SID on Windows), because gateway-api.json outlives a crash or a forced
// stop: another account that got the crashed gateway's PID and bound the port
// must not match it. It never connects to the port. A table-read error, a
// failed account check, no listener, or any other holder is false
// (rel-1-0-10:GAP-1133: the one rule for "may the route-only agents of this
// home be parked").
func HomeGatewayHoldsPort(dataDir, host string, port int) bool {
	if !filepath.IsAbs(dataDir) || port < 1 || port > 65535 {
		return false
	}
	holder, err := homeGatewayPortHolder(host, port)
	if err != nil || holder.PID <= 0 || holder.PID == os.Getpid() || !homeGatewayHolderIsThisAccount(holder) {
		return false
	}
	if New(dataDir).HasManagedProcessIdentity(holder.PID) {
		return true
	}
	return runtimeAPIRecordNames(dataDir, holder.PID, port)
}

// runtimeAPIRecordNames reports whether the private gateway-api.json of
// dataDir names pid listening on port.
func runtimeAPIRecordNames(dataDir string, pid, port int) bool {
	record := filepath.Join(filepath.Clean(dataDir), "gateway-api.json")
	if err := safefile.ValidatePrivateFile(record); err != nil {
		return false
	}
	raw, err := safefile.ReadRegularFileBounded(record, 4<<10)
	if err != nil {
		return false
	}
	var published struct {
		PID  int `json:"pid"`
		Port int `json:"port"`
	}
	return json.Unmarshal(raw, &published) == nil && published.PID == pid && published.Port == port
}
