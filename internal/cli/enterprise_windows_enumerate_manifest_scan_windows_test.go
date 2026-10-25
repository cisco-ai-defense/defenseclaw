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
	"sync/atomic"
	"testing"
	"time"

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
		"  - {user: alice, user_home: 'C:\\Users\\alice', sid: " + aliceSID + ", connector: hermes, agent_version: 0.21.5}\n" +
		"  - {user: bob, user_home: 'C:\\Users\\bob', sid: " + bobSID + ", connector: codex, agent_version: 0.140.0}\n"
	cases := []struct {
		name        string
		manifest    string
		exclude     []string
		exempt      []string
		scanErr     error
		partial     []enterprisehooks.UnprotectedAgent
		writerErr   error
		wantWritten bool
		want        []string // sid/connector/code
		wantReason  string   // in the reason of each account the scan did not inspect
	}{
		{name: "cycle deadline", manifest: authored, scanErr: context.DeadlineExceeded, wantWritten: true, wantReason: "scan timed out",
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "profile list unreadable", manifest: authored, scanErr: errors.New("registry: access denied"), wantWritten: true, wantReason: "could not be inspected this cycle",
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "excluded account stays out", manifest: authored, exclude: []string{"bob"}, scanErr: context.DeadlineExceeded, wantWritten: true,
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete"}},
		// An exempt account keeps its enabled rows: a failed scan must not
		// clear its NOT COVERED rows from the record.
		{name: "exempt account stays not covered", manifest: authored, exempt: []string{"bob"}, scanErr: context.DeadlineExceeded, wantWritten: true, wantReason: "scan timed out",
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "exempt account by SID stays not covered", manifest: authored, exempt: []string{bobSID}, scanErr: errors.New("registry: access denied"), wantWritten: true, wantReason: "could not be inspected this cycle",
			want: []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "partial findings kept once", manifest: authored, scanErr: context.Canceled, wantWritten: true, wantReason: "scan timed out",
			partial: []enterprisehooks.UnprotectedAgent{{User: "alice", SID: aliceSID, Connector: "claudecode", Code: enterprisehooks.UnprotectedCodeInstallScanIncomplete, Reason: "home"}},
			want:    []string{aliceSID + "/claudecode/agent_install_scan_incomplete", aliceSID + "/hermes/agent_install_scan_incomplete", bobSID + "/codex/agent_install_scan_incomplete"}},
		{name: "unreadable targets leave the record", manifest: "", scanErr: context.DeadlineExceeded, wantWritten: false},
		{name: "record write failure", manifest: authored, writerErr: errors.New("disk full"), wantWritten: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentManifest, ExcludeUsers: tc.exclude, ExemptUsers: tc.exempt})
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
					if tc.wantReason != "" && agent.Reason != "home" && !strings.Contains(agent.Reason, tc.wantReason) {
						t.Errorf("%s/%s reason = %q, want it to say %q", agent.SID, agent.Connector, agent.Reason, tc.wantReason)
					}
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

// Any call of the manifest-mode install scan that stalls outside a profile's
// bounded worker (an unrelated or enrolled ProfileList home on an offline
// share, a registry or account lookup that never answers) must not hold the
// cycle: Setup's --once enumeration would wait for it and roll back. The
// cycle publishes by its deadline plus a short grace, every enrolled account
// the scan did not finish is NOT COVERED with "scan timed out", and while the
// call stays stalled a later cycle answers at once and starts no second scan.
func TestEnterpriseWindowsManifestModeStalledScanPublishesByTheDeadline(t *testing.T) {
	const aliceSID = "S-1-5-21-1004336348-1177238915-682003330-1001"
	const bobSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	authored := "version: 1\ntargets:\n" +
		"  - {user: alice, user_home: 'C:\\Users\\alice', sid: " + aliceSID + ", connector: claudecode, agent_version: 2.1.187}\n" +
		"  - {user: alice, user_home: 'C:\\Users\\alice', sid: " + aliceSID + ", connector: hermes, agent_version: 0.21.5}\n" +
		"  - {user: bob, user_home: 'C:\\Users\\bob', sid: " + bobSID + ", connector: codex, agent_version: 0.140.0}\n"
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentManifest, ExemptUsers: []string{"bob"}})
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(manifest, []byte(authored), 0o600); err != nil {
		t.Fatal(err)
	}
	previousEnumerator, previousRecordWriter := enterpriseWindowsEnumerateProfileEnumerator, enterpriseWindowsEnumerateUnprotectedWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateProfileEnumerator, enterpriseWindowsEnumerateUnprotectedWriter = previousEnumerator, previousRecordWriter
	})
	release, returned := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	var calls atomic.Int32
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		calls.Add(1)
		// One finding before the stall is kept; a late one is dropped.
		opts.ReportUnprotected(enterprisehooks.UnprotectedAgent{User: "alice", SID: aliceSID, Connector: "claudecode", Code: enterprisehooks.UnprotectedCodeInstallScanIncomplete, Reason: "home"})
		opts.Logger(aliceSID, "before the stall")
		<-release
		opts.ReportUnprotected(enterprisehooks.UnprotectedAgent{User: "bob", SID: bobSID, Connector: "codex", Code: enterprisehooks.UnprotectedCodeAgentUnprotected, Reason: "late"})
		opts.Logger(bobSID, "after the stall")
		close(returned)
		return enterprisehooks.Manifest{}, nil
	}
	want := aliceSID + "/claudecode/agent_install_scan_incomplete," + aliceSID + "/hermes/agent_install_scan_incomplete," + bobSID + "/codex/agent_install_scan_incomplete"
	cycle := func(name string, guard time.Duration) {
		t.Helper()
		var published []string
		enterpriseWindowsEnumerateUnprotectedWriter = func(_ string, agents []enterprisehooks.UnprotectedAgent) (bool, error) {
			for _, agent := range agents {
				published = append(published, agent.SID+"/"+agent.Connector+"/"+agent.Code)
				if agent.Reason != "home" && !strings.Contains(agent.Reason, "scan timed out") {
					t.Errorf("%s: %s/%s reason = %q, want scan timed out", name, agent.SID, agent.Connector, agent.Reason)
				}
			}
			return true, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		var stderr bytes.Buffer
		finished := make(chan error, 1)
		go func() { finished <- publishEnterpriseWindowsManifestInstallScan(ctx, &stderr, cfg, manifest) }()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("%s: a stalled scan failed the cycle: %v", name, err)
			}
		case <-time.After(guard):
			unblock()
			t.Fatalf("%s: a stalled manifest-mode scan held the cycle past its deadline", name)
		}
		if got := strings.Join(published, ","); got != want {
			t.Fatalf("%s: published = %s, want %s", name, got, want)
		}
		if !strings.Contains(stderr.String(), "did not finish") || !strings.Contains(stderr.String(), "before the stall") {
			t.Fatalf("%s: log = %q, want the scan log and a did-not-finish warning", name, stderr.String())
		}
	}
	cycle("stalled cycle", 6*time.Second)
	// The call is still stalled: the next cycle answers at once, scan timed out.
	cycle("next cycle while stalled", time.Second)
	if got := calls.Load(); got != 1 {
		t.Fatalf("enumerator calls = %d, want 1: a cycle started a second scan behind the stalled one", got)
	}
	unblock()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled scan never returned")
	}
	time.Sleep(50 * time.Millisecond) // the worker clears its in-flight mark after returning
}
