// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
)

// fakeNative is the Security framework: one item per service/account; an
// item it adds trusts the caller, so reads ask nothing.
type fakeNative struct {
	items  map[string][]byte
	finds  int
	status int32 // forced find status (locked, declined)
}

func (f *fakeNative) find(service, account string) ([]byte, int32) {
	f.finds++
	if f.status != 0 {
		return nil, f.status
	}
	v, ok := f.items[service+"/"+account]
	if !ok {
		return nil, secItemNotFound
	}
	return append([]byte(nil), v...), 0
}

func (f *fakeNative) add(service, account string, secret []byte) int32 {
	if f.items == nil {
		f.items = map[string][]byte{}
	}
	if _, ok := f.items[service+"/"+account]; ok {
		return secDuplicateItem
	}
	f.items[service+"/"+account] = append([]byte(nil), secret...)
	return 0
}

func nativeStore(kc *fakeKeychain, n *fakeNative, dir string) *sealedStore {
	st := newMacStore(kc.run, dir)
	st.s.(*macKeySealer).native = n
	return st
}

// GAP-0165: with the native keychain the security tool is not used for a
// new key, and every later command reads it without a prompt.
func TestMacNativeKeyAsksNothing(t *testing.T) {
	dir := t.TempDir()
	kc, n := &fakeKeychain{}, &fakeNative{}
	roundTrip(t, nativeStore(kc, n, dir))
	if len(n.items) != 1 || n.items[keychainService+"/"+macNativeAccount] == nil {
		t.Fatalf("native items %v", n.items)
	}
	for _, c := range kc.calls {
		if len(c.args) > 1 && c.args[1] == "-i" {
			t.Fatal("a new key went through the security tool")
		}
	}
	// A new process (whoami, doctor) loads with the native item only.
	if err := nativeStore(kc, n, dir).Save("e1", sampleToken()); err != nil {
		t.Fatal(err)
	}
	before := len(kc.calls)
	if tok, err := nativeStore(kc, n, dir).Load("e1"); err != nil || tok == nil {
		t.Fatalf("load %v %v", tok, err)
	}
	if len(kc.calls) != before {
		t.Errorf("a read ran the security tool (%v)", kc.calls[before:])
	}
}

// A key an earlier launcher stored through the security tool is read once
// (one macOS prompt), moved to the native item, and the old item removed;
// files sealed with it still open.
func TestMacNativeMovesTheOldKey(t *testing.T) {
	dir := t.TempDir()
	kc := &fakeKeychain{}
	old := newMacStore(kc.run, dir)
	if err := old.Save("e1", sampleToken()); err != nil {
		t.Fatal(err)
	}
	legacy := kc.key
	n := &fakeNative{}
	tok, err := nativeStore(kc, n, dir).Load("e1")
	if err != nil || tok == nil {
		t.Fatalf("load after the move: %v %v", tok, err)
	}
	if string(n.items[keychainService+"/"+macNativeAccount]) != legacy {
		t.Fatal("the old key was not moved")
	}
	deleted := false
	for _, c := range kc.calls {
		if len(c.args) > 1 && c.args[1] == "delete-generic-password" && strings.Join(c.args, " ") == securityTool+" delete-generic-password -s "+keychainService+" -a "+macKeyAccount {
			deleted = true
		}
	}
	if !deleted {
		t.Error("the old item that asked on every read was not removed")
	}
}

func TestMacNativeLockedSaysWhatToDo(t *testing.T) {
	dir, kc, n := t.TempDir(), &fakeKeychain{}, &fakeNative{}
	if err := nativeStore(kc, n, dir).Save("e1", sampleToken()); err != nil {
		t.Fatal(err)
	}
	n.status = secInteractionNotAllowed
	_, err := nativeStore(kc, n, dir).Load("e1")
	if err == nil || !strings.Contains(err.Error(), "security unlock-keychain") || !strings.Contains(err.Error(), EnvTokenStore+"=file") {
		t.Fatalf("locked: %v", err)
	}
	n.status = secUserCanceled
	if _, err := nativeStore(kc, n, dir).Load("e1"); err == nil || !strings.Contains(err.Error(), "allow DefenseClaw") {
		t.Fatalf("declined: %v", err)
	}
}
