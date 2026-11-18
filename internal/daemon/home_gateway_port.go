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

// homeGatewayHolderAccount is holderAccount; tests replace it.
var homeGatewayHolderAccount = holderAccount

// homeGatewayStartIdentity is holderStartIdentity; tests replace it.
var homeGatewayStartIdentity = holderStartIdentity

// holderAccountMatch is what the account check of a port holder found.
type holderAccountMatch int

const (
	// holderOtherAccount: another account, no such process, or a lookup
	// error other than holderAccountUnreadable.
	holderOtherAccount holderAccountMatch = iota
	// holderThisAccount: the holder runs as this account.
	holderThisAccount
	// holderAccountUnreadable: Windows only. The process or its token is
	// access denied: a gateway this account started elevated or in another
	// logon session, seen from a non-elevated caller (or another account's
	// process).
	holderAccountUnreadable
)

// HomeGatewayHoldsPort reports whether the socket table shows the listener on
// host:port held by this data directory's own gateway, a process other than
// the caller: the one its PID record names with a verified executable and
// start identity (defenseclaw-gateway start), or the one its private
// gateway-api.json names for that port (written by every gateway of this home
// once it binds, so a foreground gateway counts too). The holder must run as
// this account (holderAccount: the UID on Linux and macOS, the token user SID
// on Windows), because gateway-api.json outlives a crash or a forced stop:
// another account that got the crashed gateway's PID and bound the port must
// not match it. It never connects to the port. A table-read error, a failed
// account check, no listener, or any other holder is false
// (rel-1-0-10:GAP-1133: the one rule for "may the route-only agents of this
// home be parked").
//
// A Windows gateway this account started elevated in another logon session
// (a scheduled task, an administrator's SSH session) does not open for a
// non-elevated caller, nor its token (rel-1-0-10:GAP-1164). It still holds
// the port when its creation time, which the kernel's process list gives
// without a handle, is the one its gateway-api.json recorded: that private
// record is written only by this home's gateway about itself, and a reused
// PID was created later, so it never matches. With a start identity in the
// record, this account's holder must match it too.
func HomeGatewayHoldsPort(dataDir, host string, port int) bool {
	holder, ok := homeGatewayCandidate(dataDir, host, port)
	if !ok {
		return false
	}
	switch homeGatewayHolderAccount(holder) {
	case holderAccountUnreadable:
		// gateway.pid is not a private-file record: an unreadable holder is
		// accepted only through gateway-api.json and its creation time.
		return runtimeRecordNamesProcess(dataDir, holder.PID, port)
	case holderThisAccount:
		if New(dataDir).HasManagedProcessIdentity(holder.PID) {
			return true
		}
		record, ok := readRuntimeAPIRecord(dataDir)
		if !ok || record.PID != holder.PID || record.Port != port {
			return false
		}
		if record.StartIdentity == "" {
			// A gateway older than 1.0.10 wrote no start identity: the
			// account check is all its record has, until it restarts.
			return true
		}
		return startIdentityMatches(holder.PID, record.StartIdentity)
	default:
		return false
	}
}

// HomeGatewayOutOfReach reports the PID of this data directory's own gateway
// when it holds host:port but this process may not open it or read its token:
// on Windows, a gateway this account started elevated in another logon
// session (a scheduled task, an administrator's SSH session). It is the
// unreadable branch of HomeGatewayHoldsPort, with the same binding: the
// creation time the kernel's process list gives must be the one the gateway
// recorded in its private gateway-api.json. Any other holder, a lookup error,
// no record, a record without a start identity or another creation time is
// false. It never authorizes process control or a token-bearing request;
// callers only name the gateway and refuse what they cannot do from here
// (rel-1-0-10:GAP-1212).
func HomeGatewayOutOfReach(dataDir, host string, port int) (int, bool) {
	holder, ok := homeGatewayCandidate(dataDir, host, port)
	if !ok || homeGatewayHolderAccount(holder) != holderAccountUnreadable ||
		!runtimeRecordNamesProcess(dataDir, holder.PID, port) {
		return 0, false
	}
	return holder.PID, true
}

// homeGatewayCandidate is the socket table's holder of host:port when it can
// be this home's gateway: an absolute data directory, a valid port, a holder
// PID that is not the caller.
func homeGatewayCandidate(dataDir, host string, port int) (PortHolder, bool) {
	if !filepath.IsAbs(dataDir) || port < 1 || port > 65535 {
		return PortHolder{}, false
	}
	holder, err := homeGatewayPortHolder(host, port)
	if err != nil || holder.PID <= 0 || holder.PID == os.Getpid() {
		return PortHolder{}, false
	}
	return holder, true
}

// runtimeRecordNamesProcess reports whether the private gateway-api.json of
// dataDir names pid listening on port with the start identity pid has now.
func runtimeRecordNamesProcess(dataDir string, pid, port int) bool {
	record, ok := readRuntimeAPIRecord(dataDir)
	return ok && record.PID == pid && record.Port == port &&
		record.StartIdentity != "" && startIdentityMatches(pid, record.StartIdentity)
}

// startIdentityMatches reports whether process pid is the process a record
// named by start identity; a read error or an empty identity is no match.
func startIdentityMatches(pid int, recorded string) bool {
	live, err := homeGatewayStartIdentity(pid)
	return err == nil && live != "" && live == recorded
}

// runtimeAPIRecord is the private gateway-api.json a gateway writes in its
// data directory once it binds (internal/gateway recordRuntimeAPIAddress).
type runtimeAPIRecord struct {
	PID           int    `json:"pid"`
	Port          int    `json:"port"`
	StartIdentity string `json:"start_identity"`
}

// readRuntimeAPIRecord reads the private gateway-api.json of dataDir.
func readRuntimeAPIRecord(dataDir string) (runtimeAPIRecord, bool) {
	record := filepath.Join(filepath.Clean(dataDir), "gateway-api.json")
	if err := safefile.ValidatePrivateFile(record); err != nil {
		return runtimeAPIRecord{}, false
	}
	raw, err := safefile.ReadRegularFileBounded(record, 4<<10)
	if err != nil {
		return runtimeAPIRecord{}, false
	}
	var published runtimeAPIRecord
	if json.Unmarshal(raw, &published) != nil {
		return runtimeAPIRecord{}, false
	}
	return published, true
}

// SelfStartIdentity is this process's start identity in the text its PID
// record and its gateway-api.json carry (processStartIdentity), or "" when the
// system does not say.
func SelfStartIdentity() string {
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		return ""
	}
	return identity
}
