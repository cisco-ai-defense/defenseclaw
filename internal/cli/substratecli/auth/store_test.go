// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleToken() *Token {
	return &Token{AccessToken: "acc-marker", IDToken: "id-marker", RefreshToken: "refresh-marker", Kind: KindPerson,
		Expiry: time.Unix(1_900_000_000, 0).UTC(), Issuer: "https://idp.example.test/r", Principal: "alice", Groups: []string{"dc-devs"}}
}

var markers = []string{"acc-marker", "id-marker", "refresh-marker"}

func roundTrip(t *testing.T, st Store) {
	t.Helper()
	if got, err := st.Load("e1"); err != nil || got != nil {
		t.Fatalf("empty load = %v, %v", got, err)
	}
	want := sampleToken()
	if err := st.Save("e1", want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load("e1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("load = %v, %v", got, err)
	}
	if err := st.Delete("e1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("e1"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if got, _ := st.Load("e1"); got != nil {
		t.Fatal("not deleted")
	}
	if err := st.Save("../x", want); err == nil {
		t.Fatal("bad name accepted")
	}
	for _, m := range markers {
		if strings.Contains(st.Describe(), m) {
			t.Fatal("Describe shows a secret")
		}
	}
}

func TestFileStore(t *testing.T) {
	home := setHome(t)
	st, err := openStore("file")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, st)
	if !strings.Contains(st.Describe(), EnvTokenStore+"=file") {
		t.Errorf("describe = %s", st.Describe())
	}
	if err := st.Save("e1", sampleToken()); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "substrate", "tokens", "e1.json")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode: %v %v", fi, err)
		}
	}
	if err := os.WriteFile(p, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = st.Load("e1")
	if err == nil || !strings.Contains(err.Error(), "run: defenseclaw substrate login") {
		t.Fatalf("bad file: %v", err)
	}
}

func TestOpenStoreModes(t *testing.T) {
	setHome(t)
	if _, err := openStore("vault"); err == nil || !strings.Contains(err.Error(), EnvTokenStore) {
		t.Fatalf("unknown mode: %v", err)
	}
	if runtime.GOOS == "linux" {
		t.Setenv("PATH", t.TempDir())
		_, err := openStore("")
		if err == nil || !strings.Contains(err.Error(), "secret-tool") || !strings.Contains(err.Error(), EnvTokenStore+"=file") {
			t.Fatalf("no keychain: %v", err)
		}
	}
}

// call is one helper invocation seen by a fake runner.
type call struct {
	args  []string
	stdin string
}

// fakeKeychain emulates the macOS security tool for the key item.
type fakeKeychain struct {
	calls   []call
	key     string
	failAdd bool
}

func (f *fakeKeychain) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
	f.calls = append(f.calls, call{append([]string{filepath.Base(name)}, args...), string(stdin)})
	switch {
	case len(args) > 0 && args[0] == "find-generic-password":
		if f.key == "" {
			return nil, "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n", 44, nil
		}
		return []byte(f.key + "\n"), "", 0, nil
	case len(args) == 1 && args[0] == "-i":
		if f.failAdd {
			return nil, "security: SecKeychainItemCreateFromContent: User interaction is not allowed.\n", 0, nil
		}
		fields := strings.Fields(string(stdin))
		f.key = fields[len(fields)-1]
		return []byte("security> "), "", 0, nil
	}
	return nil, "unexpected", 2, nil
}

func TestMacKeychainCommands(t *testing.T) {
	dir := t.TempDir()
	kc := &fakeKeychain{}
	st := newMacStore(kc.run, "/usr/bin/security", dir)
	roundTrip(t, st)

	want := [][]string{
		{"security", "find-generic-password", "-s", "defenseclaw-substrate", "-a", "token-key", "-w"},
		{"security", "-i"},
		{"security", "find-generic-password", "-s", "defenseclaw-substrate", "-a", "token-key", "-w"},
	}
	if len(kc.calls) != len(want) {
		t.Fatalf("calls = %d, want %d", len(kc.calls), len(want))
	}
	for i, w := range want {
		if !reflect.DeepEqual(kc.calls[i].args, w) {
			t.Errorf("call %d = %v, want %v", i, kc.calls[i].args, w)
		}
	}
	add := kc.calls[1].stdin
	if !strings.HasPrefix(add, "add-generic-password -U -s defenseclaw-substrate -a token-key -l defenseclaw-substrate-token-key -w ") || !strings.HasSuffix(add, "\n") {
		t.Errorf("add line shape is wrong")
	}
	for _, c := range kc.calls {
		for _, a := range c.args {
			if strings.Contains(a, kc.key) {
				t.Fatal("the key appears in a command argument")
			}
		}
		for _, m := range markers {
			if strings.Contains(c.stdin, m) || strings.Contains(strings.Join(c.args, " "), m) {
				t.Fatal("a token went through the security tool")
			}
		}
	}
	// The sealed file holds no plaintext token.
	if err := st.Save("e1", sampleToken()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "e1.sealed"))
	for _, m := range markers {
		if bytes.Contains(raw, []byte(m)) {
			t.Fatal("sealed file has plaintext")
		}
	}
	// A file sealed for one name does not open as another.
	if err := os.WriteFile(filepath.Join(dir, "e2.sealed"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load("e2"); err == nil || !strings.Contains(err.Error(), "run: defenseclaw substrate login") {
		t.Fatalf("swapped file: %v", err)
	}
	// A new process with the key gone.
	st2 := newMacStore((&fakeKeychain{}).run, "/usr/bin/security", dir)
	if _, err := st2.Load("e1"); err == nil || !strings.Contains(err.Error(), "key is missing") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestMacKeychainLocked(t *testing.T) {
	kc := &fakeKeychain{failAdd: true}
	st := newMacStore(kc.run, "/usr/bin/security", t.TempDir())
	err := st.Save("e1", sampleToken())
	if err == nil || !strings.Contains(err.Error(), "User interaction is not allowed") || !strings.Contains(err.Error(), EnvTokenStore+"=file") {
		t.Fatalf("err = %v", err)
	}
	noSecret(t, err, markers...)
}

// fakeSecretTool emulates secret-tool.
type fakeSecretTool struct {
	calls []call
	items map[string]string
	down  bool
}

func (f *fakeSecretTool) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
	f.calls = append(f.calls, call{append([]string{filepath.Base(name)}, args...), string(stdin)})
	if f.down {
		return nil, "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n", 1, nil
	}
	acct := args[len(args)-1]
	switch args[0] {
	case "lookup":
		v, ok := f.items[acct]
		if !ok {
			return nil, "", 1, nil
		}
		return []byte(v), "", 0, nil
	case "store":
		f.items[acct] = string(stdin)
		return nil, "", 0, nil
	case "clear":
		delete(f.items, acct)
		return nil, "", 0, nil
	}
	return nil, "unexpected", 2, nil
}

func TestSecretToolCommands(t *testing.T) {
	fs := &fakeSecretTool{items: map[string]string{}}
	st := &secretToolStore{run: fs.run, bin: "/usr/bin/secret-tool"}
	roundTrip(t, st)
	want := []struct {
		args     []string
		hasStdin bool
	}{
		{[]string{"secret-tool", "lookup", "service", "defenseclaw-substrate", "account", "e1"}, false},
		{[]string{"secret-tool", "store", "--label=DefenseClaw substrate sign-in (e1)", "service", "defenseclaw-substrate", "account", "e1"}, true},
		{[]string{"secret-tool", "lookup", "service", "defenseclaw-substrate", "account", "e1"}, false},
		{[]string{"secret-tool", "clear", "service", "defenseclaw-substrate", "account", "e1"}, false},
		{[]string{"secret-tool", "clear", "service", "defenseclaw-substrate", "account", "e1"}, false},
		{[]string{"secret-tool", "lookup", "service", "defenseclaw-substrate", "account", "e1"}, false},
	}
	if len(fs.calls) != len(want) {
		t.Fatalf("calls = %d, want %d", len(fs.calls), len(want))
	}
	for i, w := range want {
		c := fs.calls[i]
		if !reflect.DeepEqual(c.args, w.args) || (c.stdin != "") != w.hasStdin {
			t.Errorf("call %d = %v stdin=%v", i, c.args, c.stdin != "")
		}
		for _, m := range markers {
			if strings.Contains(strings.Join(c.args, " "), m) {
				t.Fatal("a token is in secret-tool arguments")
			}
		}
	}
	if !strings.Contains(fs.calls[1].stdin, "refresh-marker") {
		t.Error("the token did not go on stdin")
	}

	down := &secretToolStore{run: (&fakeSecretTool{down: true}).run, bin: "secret-tool"}
	for _, err := range []error{down.Save("e1", sampleToken()), func() error { _, err := down.Load("e1"); return err }()} {
		if err == nil || !strings.Contains(err.Error(), "D-Bus") || !strings.Contains(err.Error(), EnvTokenStore+"=file") {
			t.Fatalf("down: %v", err)
		}
		noSecret(t, err, markers...)
	}
}

func TestGCMSeal(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	ct, err := gcmSeal(key, "e1", []byte("plain"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := gcmOpen(key, "e1", ct); err != nil || string(pt) != "plain" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := gcmOpen(bytes.Repeat([]byte{8}, 32), "e1", ct); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := gcmOpen(key, "e1", []byte("junk")); err == nil {
		t.Fatal("opened junk")
	}
}
