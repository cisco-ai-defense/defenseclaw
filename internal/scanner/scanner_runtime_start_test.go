// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type startCheckInfo struct{}

func (startCheckInfo) Name() string       { return "DefenseClaw-ScannerRuntime" }
func (startCheckInfo) Size() int64        { return 0 }
func (startCheckInfo) Mode() os.FileMode  { return os.ModeDir }
func (startCheckInfo) ModTime() time.Time { return time.Time{} }
func (startCheckInfo) IsDir() bool        { return true }
func (startCheckInfo) Sys() any           { return nil }

// GAP-0490: a standalone gateway refuses to start on a scanner Python tree
// that fails the trust check, and starts when the tree passes or is absent.
func TestStandaloneGatewayStartRefusesAnUntrustedScannerRuntime(t *testing.T) {
	const root = `C:\ProgramData\Cisco\DefenseClaw-ScannerRuntime`
	present := func(string) (os.FileInfo, error) { return startCheckInfo{}, nil }
	untrusted := errors.New(`C:\ProgramData\Cisco\DefenseClaw-ScannerRuntime\0123\python: BUILTIN\Users can add files`)
	cases := []struct {
		name       string
		standalone bool
		rootErr    error
		lstat      func(string) (os.FileInfo, error)
		trust      error
		refused    string
		checked    bool
	}{
		{name: "other install", standalone: false, lstat: present, trust: untrusted},
		{name: "absent", standalone: true, lstat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }},
		{name: "trusted", standalone: true, lstat: present, checked: true},
		{name: "untrusted", standalone: true, lstat: present, trust: untrusted, checked: true, refused: "untrusted scanner runtime"},
		{name: "unreadable", standalone: true, lstat: func(string) (os.FileInfo, error) { return nil, os.ErrPermission }, refused: "read the scanner runtime folder"},
		{name: "unresolved", standalone: true, rootErr: errors.New("no ProgramData"), lstat: present, refused: "resolve the scanner runtime folder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checked := false
			check := runtimeStartCheck{
				standalone: func() bool { return tc.standalone },
				root:       func() (string, error) { return root, tc.rootErr },
				lstat:      tc.lstat,
				trustTree: func(got, label string) error {
					checked = true
					if got != root || label != "scanner Python runtime" {
						t.Fatalf("trust check of %q (%q)", got, label)
					}
					return tc.trust
				},
			}
			err := check.problem()
			if checked != tc.checked {
				t.Fatalf("trust check ran=%v, want %v", checked, tc.checked)
			}
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("start refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.refused) || !strings.Contains(err.Error(), "does not start") {
				t.Fatalf("start error = %v, want a refusal naming %q", err, tc.refused)
			}
		})
	}
}
