// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/keystore"
)

// fakeChain is the Security framework.
type fakeChain struct {
	items  map[string][]byte
	status int32
	// last is the copy Find handed out, to check the caller clears it.
	last []byte
}

func (f *fakeChain) Find(service, account string) ([]byte, int32) {
	if f.status != 0 {
		return nil, f.status
	}
	v, ok := f.items[service+"/"+account]
	if !ok {
		return nil, keystore.StatusItemNotFound
	}
	f.last = append([]byte(nil), v...)
	return f.last, 0
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
	if !bytes.Equal(fc.last, make([]byte, len(fc.last))) {
		t.Fatal("the keychain's copy of the key was not cleared")
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
	// locked: lookup answers as for a missing item (exit 1, no stderr),
	// as secret-tool does for a locked keyring whose unlock was dismissed;
	// search still lists the item.
	locked bool
	argv   [][]string
	stdin  [][]byte
}

func (f *fakeTool) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
	f.argv = append(f.argv, append([]string{name}, args...))
	f.stdin = append(f.stdin, stdin)
	key := strings.Join(args[len(args)-4:], " ")
	switch args[0] {
	case "lookup":
		v, ok := f.items[key]
		if !ok || f.locked {
			return nil, "", 1, nil
		}
		return append([]byte(nil), v...), "", 0, nil
	case "search":
		if _, ok := f.items[key]; ok {
			return []byte("[/org/freedesktop/secrets/collection/login/1]\nlabel = " + keyLabel + "\n"), "", 0, nil
		}
		return nil, "", 1, nil
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
	// secret-tool cannot tell a missing key from a locked keyring: never
	// "gone", never nil, nil.
	if k, err := s.Load("abcd"); k != nil || err == nil || !strings.Contains(err.Error(), "not found, or the keyring is locked") {
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
	if got := strings.Join(ft.argv[2][1:], " "); got != want {
		t.Fatalf("store argv = %q", got)
	}
	ft.locked = true
	if k, err := s.Load("abcd"); k != nil || err == nil || !strings.Contains(err.Error(), "holds the vault key") || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked key = %v %v", k, err)
	}
	ft.locked = false
	s.Delete("abcd")
	if k, _ := s.Load("abcd"); k != nil {
		t.Fatal("not deleted")
	}
	for _, a := range ft.argv {
		if strings.Contains(strings.Join(a, " "), "--unlock") {
			t.Fatal("a search unlocked the keyring")
		}
	}
	failing := secretService{t: keystore.SecretTool{Bin: "secret-tool", Run: func(context.Context, []byte, string, ...string) ([]byte, string, int, error) {
		return nil, "Cannot autolaunch D-Bus without X11 $DISPLAY\nmore", 1, nil
	}}}
	if _, err := failing.Load("abcd"); err == nil || !strings.Contains(err.Error(), "D-Bus") || strings.Contains(err.Error(), "more") {
		t.Fatalf("no dbus = %v", err)
	}
}

// A sealed vault whose Secret Service key is locked away (or the unlock
// was dismissed) is refused with a message that does not tell the person
// to discard the vault: the key is not known to be gone.
func TestVaultKeysSecretServiceLockedVault(t *testing.T) {
	ft := &fakeTool{items: map[string][]byte{}}
	ks := secretService{t: keystore.SecretTool{Run: ft.run, Bin: "/usr/bin/secret-tool"}}
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	ft.locked = true
	for _, gone := range []bool{false, true} {
		if gone {
			ft.items = map[string][]byte{}
		}
		_, _, err := OpenWith(s.Dir(), ks).Resolve("A")
		if !errors.Is(err, ErrKeyUnavailable) || !strings.Contains(err.Error(), "locked") ||
			strings.Contains(err.Error(), "aside") || strings.Contains(err.Error(), "add the secrets again") {
			t.Fatalf("gone=%v: %v", gone, err)
		}
	}
	ft.locked = false
	if _, err := s.Hint("A"); err != nil {
		t.Fatalf("cached key: %v", err)
	}
}

// decodeKey takes exactly a 32-byte key in hex, around spaces.
func TestVaultKeysDecode(t *testing.T) {
	enc := hexKey(testKey())
	if k, err := decodeKey(append(append([]byte(" "), enc...), '\n')); err != nil || !bytes.Equal(k, testKey()) {
		t.Fatalf("decode = %v", err)
	}
	for _, bad := range [][]byte{enc[:62], append(enc, 'a', 'b'), []byte("zz")} {
		if _, err := decodeKey(bad); err == nil {
			t.Fatalf("decoded %d bytes", len(bad))
		}
	}
}
