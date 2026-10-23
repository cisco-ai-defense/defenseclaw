// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// W2B-G-enum review loop 3: the enumerator joined one user's failed Claude
// Code record into the refresh result, so the gateway refused every MCP
// tool call, other users' and every Kiro call included. The publication now
// returns what it did not publish by connector and account; a folder that
// could not be written names its connector.
func TestPublishEnterpriseWindowsMCPServersNamesWhatItDidNotPublish(t *testing.T) {
	previousClaude, previousKiro := enterpriseWindowsClaudeMCPSpoolWriter, enterpriseWindowsKiroMCPSpoolWriter
	t.Cleanup(func() {
		enterpriseWindowsClaudeMCPSpoolWriter, enterpriseWindowsKiroMCPSpoolWriter = previousClaude, previousKiro
	})
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{})
	cfg.DataDir = t.TempDir()
	alice := &enterprisehooks.MCPSpoolRecordError{Connector: "claudecode", SID: "S-1-5-21-1-1001", Home: `C:\Users\alice`,
		Err: errors.New("S-1-5-21-1-1001.json not updated, previous record withdrawn: there is not enough space on the disk")}
	type writer = func(string, enterprisehooks.Manifest, func(string) error, func(string, ...any)) error
	answer := func(err error) writer {
		return func(string, enterprisehooks.Manifest, func(string) error, func(string, ...any)) error { return err }
	}

	enterpriseWindowsClaudeMCPSpoolWriter, enterpriseWindowsKiroMCPSpoolWriter = answer(errors.Join(nil, alice)), answer(nil)
	var stderr bytes.Buffer
	err := publishEnterpriseWindowsMCPServers(cfg, enterprisehooks.Manifest{}, &stderr)
	var incomplete *mcpasuser.RefreshIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("publish = %T %v, want *mcpasuser.RefreshIncomplete", err, err)
	}
	if len(incomplete.Connectors) != 0 || len(incomplete.Records) != 1 || incomplete.Records[0].SID != alice.SID {
		t.Fatalf("incomplete = %+v, want alice's Claude Code record only", incomplete)
	}
	if incomplete.Refuses("kiro", `C:\Users\alice`) || incomplete.Refuses("claudecode", `C:\Users\bob`) || !incomplete.Refuses("claudecode", `C:\Users\alice`) {
		t.Fatalf("incomplete = %+v refuses the wrong calls", incomplete)
	}

	// A Kiro folder that cannot be written refuses every Kiro call, and
	// Claude Code stays decided per record.
	enterpriseWindowsKiroMCPSpoolWriter = answer(errors.New("create kiro mcp spool: access denied"))
	err = publishEnterpriseWindowsMCPServers(cfg, enterprisehooks.Manifest{}, &stderr)
	if !errors.As(err, &incomplete) || len(incomplete.Connectors) != 1 || incomplete.Connectors[0] != "kiro" ||
		!incomplete.Refuses("kiro", `C:\Users\bob`) || incomplete.Refuses("claudecode", `C:\Users\bob`) {
		t.Fatalf("publish = %+v, want every Kiro call refused and only alice's Claude Code call", err)
	}

	enterpriseWindowsClaudeMCPSpoolWriter, enterpriseWindowsKiroMCPSpoolWriter = answer(nil), answer(nil)
	if err := publishEnterpriseWindowsMCPServers(cfg, enterprisehooks.Manifest{}, &stderr); err != nil {
		t.Fatalf("complete publication = %v", err)
	}
}
