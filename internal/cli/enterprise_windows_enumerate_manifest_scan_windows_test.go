//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// Manifest mode never decides targets from the install scan, so a scan that
// did not finish (the cycle ran out of time, ProfileList was unreadable) must
// not fail the cycle: Setup's --once enumeration would abort the install. The
// accounts it did not inspect are published incomplete instead.
func TestEnterpriseWindowsManifestModeScanFailureNeverFailsTheCycle(t *testing.T) {
	const aliceSID = "S-1-5-21-1004336348-1177238915-682003330-1001"
	const bobSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	authored := "version: 1\ntargets:\n" +
		"  - {user: alice, user_home: 'C:\\Users\\alice', sid: " + aliceSID + ", connector: claudecode, agent_version: 2.1.187}\n" +
		"  - {user: alice, user_home: 'C:\\Users\\alice', sid: " + aliceSID + ", connector: hermes, agent_version: 0.11.0}\n" +
		"  - {user: bob, user_home: 'C:\\Users\\bob', sid: " + bobSID + ", connector: codex, agent_version: 0.120.0}\n"
	cases := []struct {
		name        string
		manifest    string
		exclude     []string
		scanErr     error
		partial     []enterprisehooks.UnprotectedAgent
		writerErr   error
		wantWritten bool
		want        []string // sid/connector/code
	}{
		{name: "cycle deadline", manifest: authored, scanErr: context.DeadlineExceeded, wantWritten: true,
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "profile list unreadable", manifest: authored, scanErr: errors.New("registry: access denied"), wantWritten: true,
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "excluded account stays out", manifest: authored, exclude: []string{"bob"}, scanErr: context.DeadlineExceeded, wantWritten: true,
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete"}},
		{name: "partial findings kept once", manifest: authored, scanErr: context.Canceled, wantWritten: true,
			partial: []enterprisehooks.UnprotectedAgent{{User: "alice", SID: aliceSID, Connector: "claudecode", Code: enterprisehooks.UnprotectedCodeInstallScanIncomplete, Reason: "home"}},
			want:    []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "unreadable targets leave the record", manifest: "", scanErr: context.DeadlineExceeded, wantWritten: false},
		{name: "record write failure", manifest: authored, writerErr: errors.New("disk full"), wantWritten: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentManifest, ExcludeUsers: tc.exclude})
			manifest := filepath.Join(t.TempDir(), "targets.yaml")
			if tc.manifest != "" {
				if err := os.WriteFile(manifest, []byte(tc.manifest), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previousEnumerator, previousRecordWriter := enterpriseWindowsEnumerateProfileEnumerator, enterpriseWindowsEnumerateUnprotectedWriter
			t.Cleanup(func() {
				enterpriseWindowsEnumerateProfileEnumerator, enterpriseWindowsEnumerateUnprotectedWriter = previousEnumerator, previousRecordWriter
			})
			enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
				for _, agent := range tc.partial {
					opts.ReportUnprotected(agent)
				}
				return enterprisehooks.Manifest{}, tc.scanErr
			}
			written := false
			var published []string
			enterpriseWindowsEnumerateUnprotectedWriter = func(_ string, agents []enterprisehooks.UnprotectedAgent) (bool, error) {
				written = true
				for _, agent := range agents {
					published = append(published, agent.SID+"/"+agent.Connector+"/"+agent.Code)
				}
				return true, tc.writerErr
			}
			var stderr bytes.Buffer
			if err := publishEnterpriseWindowsManifestInstallScan(context.Background(), &stderr, cfg, manifest); err != nil {
				t.Fatalf("manifest-mode scan failure failed the cycle: %v\n%s", err, stderr.String())
			}
			if written != tc.wantWritten {
				t.Fatalf("record written = %t, want %t\n%s", written, tc.wantWritten, stderr.String())
			}
			if strings.Join(published, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("published = %v, want %v", published, tc.want)
			}
			if (tc.scanErr != nil || tc.writerErr != nil) && !strings.Contains(stderr.String(), "WARN") {
				t.Fatalf("an unfinished scan must warn; log:\n%s", stderr.String())
			}
		})
	}
}
