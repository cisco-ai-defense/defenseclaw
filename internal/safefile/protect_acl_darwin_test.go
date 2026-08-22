// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package safefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProtectPrivateACLDarwinRemovesThenValidatesExactPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat fixture: %v", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}

	var calls [][]string
	run := func(_ context.Context, executable string, args ...string) ([]byte, error) {
		call := append([]string{executable}, args...)
		calls = append(calls, call)
		switch executable {
		case "/bin/chmod":
			return nil, nil
		case "/bin/ls":
			return []byte("-rw------- 1 owner staff 3 Jan 1 00:00 " + absolute + "\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	if err := protectPrivateACLWithCommand(path, expected, time.Second, run); err != nil {
		t.Fatalf("protectPrivateACLWithCommand: %v", err)
	}
	want := [][]string{
		{"/bin/chmod", "-N", absolute},
		{"/bin/ls", "-lde", "--", absolute},
	}
	if len(calls) != len(want) {
		t.Fatalf("commands = %#v, want %#v", calls, want)
	}
	for i := range want {
		if strings.Join(calls[i], "\x00") != strings.Join(want[i], "\x00") {
			t.Fatalf("command %d = %#v, want %#v", i, calls[i], want[i])
		}
	}
}

func TestProtectPrivateACLDarwinRejectsResidualAllowEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat fixture: %v", err)
	}

	run := func(_ context.Context, executable string, _ ...string) ([]byte, error) {
		if executable == "/bin/chmod" {
			return nil, nil
		}
		return []byte("-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: group:everyone allow read\n"), nil
	}
	err = protectPrivateACLWithCommand(path, expected, time.Second, run)
	if err == nil || !strings.Contains(err.Error(), "allow ACL entry") {
		t.Fatalf("protection error = %v, want residual allow-ACL refusal", err)
	}
}

func TestValidateDarwinPrivateACLOutputUsesPrivateAuthorityPolicy(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr string
	}{
		{
			name:    "non-owner read-only allow",
			output:  "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: group:everyone allow read,readattr\n",
			wantErr: "allow ACL entry",
		},
		{
			name:    "write-capable allow",
			output:  "drwx------+ 2 owner staff 64 Jan 1 00:00 backups\n 0: group:everyone allow add_file,delete_child\n",
			wantErr: "allow ACL entry",
		},
		{
			name:    "owner-specific allow",
			output:  "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: user:owner allow read\n",
			wantErr: "allow ACL entry",
		},
		{
			name:   "deny entry",
			output: "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: group:everyone deny write\n",
		},
		{
			name:   "allow in principal with deny authority",
			output: "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: user:display allow name deny write\n",
		},
		{
			name:    "unparseable advertised ACL",
			output:  "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n",
			wantErr: "cannot interpret",
		},
		{
			name:    "unparseable mode header",
			output:  "unexpected output without an ACL entry\n",
			wantErr: "cannot interpret",
		},
		{
			name:    "unparseable numbered entry",
			output:  "-rw-------+ 1 owner staff 3 Jan 1 00:00 private.json\n 0: group:everyone unknown read\n",
			wantErr: "cannot interpret",
		},
		{
			name:   "acl-free pathname containing allow",
			output: "-rw------- 1 owner staff 3 Jan 1 00:00 path allow read\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDarwinPrivateACLOutput("/fixture", []byte(test.output))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateDarwinPrivateACLOutput: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validation error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestProtectPrivateACLDarwinFailsClosedOnCommandError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat fixture: %v", err)
	}

	commands := 0
	run := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		commands++
		return nil, errors.New("fixture failure")
	}
	err = protectPrivateACLWithCommand(path, expected, time.Second, run)
	if err == nil || !strings.Contains(err.Error(), "remove macOS ACL") {
		t.Fatalf("protection error = %v, want removal failure", err)
	}
	if commands != 1 {
		t.Fatalf("commands = %d, want 1", commands)
	}
}

func TestValidatePrivateACLDarwinInspectionTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat fixture: %v", err)
	}

	run := func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	err = validatePrivateACLWithCommand(path, expected, time.Millisecond, run)
	if err == nil || !strings.Contains(err.Error(), "timed out after 1ms") {
		t.Fatalf("validation error = %v, want bounded timeout", err)
	}
}
