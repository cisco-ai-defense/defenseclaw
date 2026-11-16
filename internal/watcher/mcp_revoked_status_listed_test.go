// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// replaceWithRefusedLauncher edits the listed entry into a local definition
// the scanner refuses, as an agent config edit does while the connection to
// the first definition lives on.
func (f *removableEntryFixture) replaceWithRefusedLauncher() {
	f.server.URL = ""
	f.server.Command = "python3"
	f.server.Args = []string{"server.py", "2"}
	f.server.LocalRefusal = "launcher"
}

func (f *removableEntryFixture) query() MCPAdmissionQuery {
	return MCPAdmissionQuery{Connector: f.server.Connector, Server: f.server.Name, Home: f.server.Home}
}

// The first definition was admitted by an allow and is replaced by a refused
// one, and the allow is then written for the replacement: the revoked status
// of the first definition tells when it left the config and what the listed
// replacement is, so a session that started later is judged on the
// replacement, which the exact allow admits (GAP-1016).
func TestRevokedStatusNamesTheAllowedReplacementForSessionsThatStartLater(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	before := time.Now()
	f.replaceWithRefusedLauncher()
	f.status()
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, Command: f.server.Command, ArgsPrefix: f.server.Args}}
	f.w.runRescanCycle(context.Background())
	f.admitQueued()
	status := f.w.MCPAdmissionStatus(f.query())
	if !status.Failed || !status.Revoked || status.Departed.Before(before) || status.Departed.After(time.Now()) {
		t.Fatalf("the call after the allow of the replacement: %+v, want the revoked first definition with its departure time", status)
	}
	if status.Listed == nil || status.Listed.Failed || status.Listed.Pending || status.Listed.Unavailable {
		t.Fatalf("listed replacement %+v, want it admitted", status.Listed)
	}
}

// Benign twin: a replacement no allow covers keeps its own refusal for the
// sessions that start later, and the first definition keeps the status for
// the ones that may still hold it.
func TestRevokedStatusNamesTheRefusedReplacementWhenNoAllowCoversIt(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.replaceWithRefusedLauncher()
	f.status()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.w.runRescanCycle(context.Background())
	f.admitQueued()
	status := f.w.MCPAdmissionStatus(f.query())
	if !status.Failed || !status.Revoked || status.Departed.IsZero() {
		t.Fatalf("the call with no allow: %+v, want the revoked first definition", status)
	}
	if status.Listed == nil || !status.Listed.Failed || status.Listed.ScanIssue != MCPScanIssueLauncher {
		t.Fatalf("listed replacement %+v, want its own launcher refusal", status.Listed)
	}
}

// A listing that cannot be read does not say what is listed or when the first
// definition left, so the revoked status stands for every session.
func TestRevokedStatusOfAnUnreadableSourceStandsForEverySession(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.replaceWithRefusedLauncher()
	f.status()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return nil, errors.New("agent config unreadable")
	})
	status := f.w.MCPAdmissionStatus(f.query())
	if !status.Failed || !status.Revoked || !status.Departed.IsZero() || status.Listed != nil {
		t.Fatalf("source unreadable: %+v, want the revoked status with no departure time and no listed status", status)
	}
}
