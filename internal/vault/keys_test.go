// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/keystore"
)

// fakeChain is the Security framework.
type fakeChain struct {
	items  map[string][]byte
	status int32
}

func (f *fakeChain) Find(service, account string) ([]byte, int32) {
	if f.status != 0 {
		return nil, f.status
	}
	v, ok := f.items[service+"/"+account]
	if !ok {
		return nil, keystore.StatusItemNotFound
	}
	return v, 0
}

func (f *fakeChain) Add(service, account string, secret []byte) int32 {
	if f.status != 0 {
		return f.status
	}
	if _, ok := f.items[service+"/"+account]; ok {
		return keystore.StatusDuplicateItem
	}
	f.items[service+"/"+account] = append([]byte(nil), secret...)
	return 0
}

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestVaultKeysMacKeychain(t *testing.T) {
	fc := &fakeChain{items: map[string][]byte{}}
	m := macKeychain{k: fc}
	if k, err := m.Load("0123"); k != nil || err != nil {
		t.Fatalf("missing key = %v %v", k, err)
	}
	if err := m.Save("0123", testKey()); err != nil {
		t.Fatal(err)
	}
	if fc.items[keyService+"/vault-0123"] == nil {
		t.Fatalf("items = %v", fc.items)
	}
	if k, err := m.Load("0123"); err != nil || !bytes.Equal(k, testKey()) {
		t.Fatalf("load = %v", err)
	}
	if err := m.Save("0123", testKey()); err == nil {
		t.Fatal("a second key for one id was saved")
	}
	fc.status = keystore.StatusInteractionNotAllowed
	if _, err := m.Load("0123"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked = %v", err)
	}
	fc.status = 0
	fc.items[keyService+"/vault-bad"] = []byte("not hex")
	if _, err := m.Load("bad"); err == nil {
		t.Fatal("a junk item read as a key")
	}
}

// fakeTool is secret-tool: it records arguments and stdin.
type fakeTool struct {
	items map[string][]byte
	argv  [][]string
	stdin [][]byte
}

func (f *fakeTool) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
	f.argv = append(f.argv, append([]string{name}, args...))
	f.stdin = append(f.stdin, stdin)
	key := strings.Join(args[len(args)-4:], " ")
	switch args[0] {
	case "lookup":
		v, ok := f.items[key]
		if !ok {
			return nil, "", 1, nil
		}
		return v, "", 0, nil
	case "store":
		f.items[key] = append([]byte(nil), stdin...)
		return nil, "", 0, nil
	case "clear":
		delete(f.items, key)
		return nil, "", 0, nil
	}
	return nil, "no such command", 2, nil
}

func TestVaultKeysSecretService(t *testing.T) {
	ft := &fakeTool{items: map[string][]byte{}}
	s := secretService{t: keystore.SecretTool{Run: ft.run, Bin: "/usr/bin/secret-tool"}}
	if k, err := s.Load("abcd"); k != nil || err != nil {
		t.Fatalf("missing key = %v %v", k, err)
	}
	if err := s.Save("abcd", testKey()); err != nil {
		t.Fatal(err)
	}
	for _, a := range ft.argv {
		if strings.Contains(strings.Join(a, " "), hex.EncodeToString(testKey())) {
			t.Fatal("the key went into an argument")
		}
	}
	if k, err := s.Load("abcd"); err != nil || !bytes.Equal(k, testKey()) {
		t.Fatalf("load = %v", err)
	}
	want := "store --label=" + keyLabel + " service " + keyService + " account vault-abcd"
	if got := strings.Join(ft.argv[1][1:], " "); got != want {
		t.Fatalf("store argv = %q", got)
	}
	s.Delete("abcd")
	if k, _ := s.Load("abcd"); k != nil {
		t.Fatal("not deleted")
	}
	failing := secretService{t: keystore.SecretTool{Bin: "secret-tool", Run: func(context.Context, []byte, string, ...string) ([]byte, string, int, error) {
		return nil, "Cannot autolaunch D-Bus without X11 $DISPLAY\nmore", 1, nil
	}}}
	if _, err := failing.Load("abcd"); err == nil || !strings.Contains(err.Error(), "D-Bus") || strings.Contains(err.Error(), "more") {
		t.Fatalf("no dbus = %v", err)
	}
}
