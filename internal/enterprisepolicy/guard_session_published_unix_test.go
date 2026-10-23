//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// withoutPublishedSessionACL records the reader grant instead of changing
// the temporary folder's access list (not every test filesystem has ACLs).
func withoutPublishedSessionACL(t *testing.T) {
	t.Helper()
	previous := publishedSessionGrantReader
	publishedSessionGrantReader = func(string, uint32) error { return nil }
	t.Cleanup(func() { publishedSessionGrantReader = previous })
}

func publishedSessionTestIdentity(*testing.T) string { return strconv.Itoa(os.Geteuid()) }

func publishedSessionOtherIdentity(identity string) string {
	if identity == "4242" {
		return "4343"
	}
	return "4242"
}

// The hook trusts a record only when it and every folder above it belong
// to root or the gateway service uid from the runtime descriptor and no
// group or other can write them; a test file under the test account's temp
// folder fails each way.
func TestValidatePublishedSessionPathRefusesWhatTheUserCanChange(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every test file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "copilot-p-x.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublishedSessionPath(path, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), "not root or the gateway service account") {
		t.Fatalf("a record the user owns must be refused: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublishedSessionPath(path, PublishedSessionTrust{ServiceUID: os.Geteuid()}); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("a record others can write must be refused: %v", err)
	}
	link := filepath.Join(dir, "copilot-p-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublishedSessionPath(link, PublishedSessionTrust{ServiceUID: os.Geteuid()}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a link must be refused: %v", err)
	}
}

// The gateway writes its records only in a folder that is its own: a
// per-account folder another account owns or can write is replaced, and
// the grant runs for the account's uid.
func TestPublishedSessionPrepareReplacesAFolderThatIsNotTheGateways(t *testing.T) {
	granted := []uint32{}
	previous := publishedSessionGrantReader
	publishedSessionGrantReader = func(_ string, uid uint32) error { granted = append(granted, uid); return nil }
	t.Cleanup(func() { publishedSessionGrantReader = previous })
	root := t.TempDir()
	dir, _ := PublishedSessionIdentityDir(root, "4242")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "copilot-p-planted.json")
	if err := os.WriteFile(planted, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishedSessionPrepare(root, dir, "4242"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the folder must be recreated 0700: %v %v", info, err)
	}
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Fatal("a record in a folder that was not the gateway's must go with it")
	}
	if len(granted) != 1 || granted[0] != 4242 {
		t.Fatalf("the account must be granted read once: %v", granted)
	}
	if err := publishedSessionPrepare(root, dir, "4242"); err != nil || len(granted) != 1 {
		t.Fatalf("an intact folder is kept: %v %v", err, granted)
	}
}

// Kill switch: the key file is root's alone. The gateway may remove it (it
// owns the folder the key is in) but never make one: the hook's trust check
// refuses a key the gateway service uid owns (it accepts that uid for a
// record), and the key read skips it.
func TestThePublishedSessionKeyMustBeRoots(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every test file")
	}
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	path, err := createAccountTestKey(root, publishedSessionTestIdentity(t), PublishedSessionTrust{})
	if err != nil {
		t.Fatal(err)
	}
	service := PublishedSessionTrust{ServiceUID: os.Geteuid()}
	if err := ValidatePublishedSessionPath(path, service); err == nil || !strings.HasSuffix(err.Error(), ", not root") {
		t.Fatalf("a key file of the gateway service uid must be refused: %v", err)
	}
	record := filepath.Join(root, "copilot-p-x.json")
	if err := os.WriteFile(record, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublishedSessionPath(record, service); err != nil && strings.HasSuffix(err.Error(), ", not root") {
		t.Fatalf("a record of the gateway service uid is not refused for its owner: %v", err)
	}
	if _, err := ReadPublishedSessionKey(root, publishedSessionTestIdentity(t)); err == nil {
		t.Fatal("a key file root does not own must be no key")
	}
	if err := RevokePublishedSessionKey(root, publishedSessionTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the kill only removes root's keys: %v", err)
	}
}
