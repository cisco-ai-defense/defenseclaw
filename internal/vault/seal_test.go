// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKeys is an in-memory keystore that counts every call.
type fakeKeys struct {
	mu      sync.Mutex
	id      string
	items   map[string][]byte
	loadErr error
	saveErr error
	calls   int
}

func newFakeKeys() *fakeKeys { return &fakeKeys{id: keystoreMac, items: map[string][]byte{}} }

func (f *fakeKeys) Name() string { return keystoreName(f.id) }
func (f *fakeKeys) ID() string   { return f.id }

func (f *fakeKeys) Load(id string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	v, ok := f.items[id]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeKeys) Save(id string, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.items[id] = append([]byte(nil), key...)
	return nil
}

func (f *fakeKeys) Delete(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	delete(f.items, id)
}

func (f *fakeKeys) count() (calls, items int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, len(f.items)
}

func withClock(s *Store) *Store {
	clock := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); clock = clock.Add(time.Second); return clock }
	return s
}

func sealedStore(t *testing.T, ks Keystore) *Store {
	t.Helper()
	return withClock(OpenWith(filepath.Join(t.TempDir(), "vault"), ks))
}

func rawVault(t *testing.T, s *Store) []byte {
	t.Helper()
	b, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustNotHold(t *testing.T, raw []byte, values ...string) {
	t.Helper()
	for _, v := range values {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("the vault file holds a value in the clear")
		}
	}
}

func fileVersionOf(t *testing.T, raw []byte) int {
	t.Helper()
	var v struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v.Version
}

// A vault the CLI writes with a usable keystore is sealed: no value in the
// file, the values open with the key, the storage line says so.
func TestVaultSealRoundTrip(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if n := s.Notice(); !strings.Contains(n, "now sealed") || !strings.Contains(n, "macOS Keychain") {
		t.Fatalf("notice = %q", n)
	}
	if _, err := s.Add(AddInput{Name: "ANTHROPIC_API_KEY", Value: fakeAnthropic(), Host: "api.anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	raw := rawVault(t, s)
	mustNotHold(t, raw, "value-a", fakeAnthropic())
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatalf("version = %d", fileVersionOf(t, raw))
	}
	// POSIX permission bits only: Windows reports no owner-only mode
	// (TestFileIsPrivate skips there for the same reason, GAP-2000).
	if fi, _ := os.Stat(s.Path()); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	for name, want := range map[string]string{"A": "value-a", "ANTHROPIC_API_KEY": fakeAnthropic()} {
		if _, v, err := OpenWith(s.Dir(), ks).Resolve(name); err != nil || v != want {
			t.Fatalf("resolve %s: %v", name, err)
		}
	}
	st, err := s.Storage()
	if err != nil || st.Mode != "sealed" || st.Label != "sealed (macOS Keychain)" {
		t.Fatalf("storage = %+v %v", st, err)
	}
	// Only the capturable value carries a fingerprint.
	var f file
	_ = json.Unmarshal(raw, &f)
	for _, r := range f.Entries {
		if (r.FP != "") != (r.Name == "ANTHROPIC_API_KEY") {
			t.Fatalf("fingerprint on %s = %v", r.Name, r.FP != "")
		}
	}
	if _, err := s.Add(AddInput{Name: "B", Value: "value-a", Host: "api.example.com"}); err == nil {
		t.Fatal("a sealed vault took a value it holds twice")
	}
	ss := newFakeKeys()
	ss.id = keystoreSecretService
	s2 := sealedStore(t, ss)
	if _, err := s2.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := s2.Storage(); st.Label != "sealed (Secret Service)" {
		t.Fatalf("storage = %+v", st)
	}
}

// Replace, bind, rename and remove keep a sealed vault sealed, and a value
// still opens under its new name and host.
func TestVaultSealChangesReseal(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind("A", "api.example.org:8443"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rename("A", "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceValue("B", "value-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUsed([]string{"B"}, "sb1"); err != nil {
		t.Fatal(err)
	}
	e, v, err := OpenWith(s.Dir(), ks).Resolve("B")
	if err != nil || v != "value-b" || e.Target() != "api.example.org:8443" || e.UseCount != 1 {
		t.Fatalf("resolve = %+v %v", e, err)
	}
	if err := s.Remove("B"); err != nil {
		t.Fatal(err)
	}
	raw := rawVault(t, s)
	mustNotHold(t, raw, "value-a", "value-b")
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("an emptied sealed vault went back to a file")
	}
}

// A sealed value is bound to its entry name and host: moving it or
// re-pointing the host in the file makes it fail to open (fail closed).
func TestVaultSealBindsNameAndHost(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	for _, n := range []string{"A", "B"} {
		if _, err := s.Add(AddInput{Name: n, Value: "value-" + n, Host: "api.example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	orig := rawVault(t, s)
	tamper := func(edit func(f *file)) {
		t.Helper()
		var f file
		if err := json.Unmarshal(orig, &f); err != nil {
			t.Fatal(err)
		}
		edit(&f)
		b, _ := json.Marshal(f)
		if err := os.WriteFile(s.Path(), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tamper(func(f *file) { f.Entries[0].Host = "evil.example.net" })
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); !errors.Is(err, ErrDamaged) {
		t.Fatalf("re-pointed host opened: %v", err)
	}
	tamper(func(f *file) { f.Entries[0].Sealed, f.Entries[1].Sealed = f.Entries[1].Sealed, f.Entries[0].Sealed })
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); !errors.Is(err, ErrDamaged) {
		t.Fatalf("swapped value opened: %v", err)
	}
	before := rawVault(t, s)
	if _, err := OpenWith(s.Dir(), ks).Add(AddInput{Name: "C", Value: "value-c", Host: "api.example.com"}); !errors.Is(err, ErrDamaged) {
		t.Fatalf("add on a damaged vault: %v", err)
	}
	if !bytes.Equal(before, rawVault(t, s)) {
		t.Fatal("a damaged vault was written over")
	}
}

// No usable keystore: the vault stays an owner-only file, the change says
// why, and the storage line says it is not encrypted.
func TestVaultSealFallsBackToFile(t *testing.T) {
	s := sealedStore(t, nil)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if n := s.Notice(); !strings.Contains(n, "not encrypted") {
		t.Fatalf("notice = %q", n)
	}
	raw := rawVault(t, s)
	if fileVersionOf(t, raw) != fileVersion || !bytes.Contains(raw, []byte("value-a")) {
		t.Fatal("not a file vault")
	}
	// POSIX permission bits only: Windows reports no owner-only mode
	// (TestFileIsPrivate skips there for the same reason, GAP-2000).
	if fi, _ := os.Stat(s.Path()); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	st, _ := s.Storage()
	if st.Mode != "file" || st.Label != StorageFileLabel || st.Note == "" {
		t.Fatalf("storage = %+v", st)
	}

	// A keystore that cannot keep the key: still a file, and the reason.
	ks := newFakeKeys()
	ks.saveErr = errors.New("the macOS keychain is locked")
	s2 := sealedStore(t, ks)
	if _, err := s2.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if n := s2.Notice(); !strings.Contains(n, "locked") {
		t.Fatalf("notice = %q", n)
	}
	if fileVersionOf(t, rawVault(t, s2)) != fileVersion {
		t.Fatal("sealed without a key")
	}
}

// DEFENSECLAW_VAULT_STORE=file keeps a new vault a file; an unknown value
// is refused.
func TestVaultSealEnvForcesFile(t *testing.T) {
	t.Setenv(EnvStore, "file")
	s := withClock(OpenWithKeystore(filepath.Join(t.TempDir(), "vault")))
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Storage()
	if st.Mode != "file" || !strings.Contains(st.Note, EnvStore+"=file") {
		t.Fatalf("storage = %+v", st)
	}
	t.Setenv(EnvStore, "plaintext")
	if _, err := s.Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); err == nil || !strings.Contains(err.Error(), EnvStore) {
		t.Fatalf("unknown store value: %v", err)
	}
}

// An existing file vault is sealed by the next CLI change, with nothing
// left in the clear next to it.
func TestVaultSealMigratesFileVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	plain := withClock(Open(dir))
	for _, n := range []string{"A", "B"} {
		if _, err := plain.Add(AddInput{Name: n, Value: "value-" + n, Host: "api.example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	ks := newFakeKeys()
	// A change that fails makes no key and leaves the file as it is.
	if err := OpenWith(dir, ks).Remove("MISSING"); !IsNotFound(err) {
		t.Fatal(err)
	}
	if _, items := ks.count(); items != 0 {
		t.Fatal("a failed change made a key")
	}
	cli := withClock(OpenWith(dir, ks))
	if err := cli.MarkUsed([]string{"A"}, "sb1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli.Notice(), "now sealed") {
		t.Fatal("no notice")
	}
	raw := rawVault(t, cli)
	mustNotHold(t, raw, "value-A", "value-B")
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("not sealed")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != FileName && e.Name() != "vault.lock" {
			t.Fatalf("left behind: %s", e.Name())
		}
	}
	for _, n := range []string{"A", "B"} {
		if _, v, err := OpenWith(dir, ks).Resolve(n); err != nil || v != "value-"+n {
			t.Fatalf("resolve %s: %v", n, err)
		}
	}
}

// A sealed vault is never written back as a file: without the key (no
// keystore, forced file, the daemon) a change that needs the values fails
// and leaves the file alone; one that does not keeps the vault sealed.
func TestVaultSealNeverRewrittenAsFile(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	for _, n := range []string{"A", "B"} {
		if _, err := s.Add(AddInput{Name: n, Value: "value-" + n, Host: "api.example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(EnvStore, "file")
	stores := map[string]*Store{
		"no keystore": OpenWith(s.Dir(), nil),
		"forced file": OpenWithKeystore(s.Dir()),
		"daemon":      Open(s.Dir()),
	}
	for name, st := range stores {
		before := rawVault(t, s)
		if _, err := st.Add(AddInput{Name: "C", Value: "value-c", Host: "api.example.com"}); !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("%s: add = %v", name, err)
		}
		if _, err := st.Bind("A", "api.example.org"); !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("%s: bind = %v", name, err)
		}
		if _, _, err := st.Resolve("A"); !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("%s: resolve = %v", name, err)
		}
		if !bytes.Equal(before, rawVault(t, s)) {
			t.Fatalf("%s: a refused change wrote the vault", name)
		}
		if err := st.MarkUsed([]string{"A"}, "sb1"); err != nil {
			t.Fatalf("%s: mark used = %v", name, err)
		}
		raw := rawVault(t, s)
		if fileVersionOf(t, raw) != sealedVersion {
			t.Fatalf("%s: written as a file", name)
		}
		mustNotHold(t, raw, "value-A", "value-B")
		if list, err := st.List(); err != nil || len(list) != 2 {
			t.Fatalf("%s: list = %v %v", name, list, err)
		}
		if lab, _ := st.Storage(); lab.Mode != "sealed" {
			t.Fatalf("%s: storage = %+v", name, lab)
		}
	}
	if err := OpenWith(s.Dir(), nil).Remove("B"); err != nil {
		t.Fatal(err)
	}
	if _, v, err := OpenWith(s.Dir(), ks).Resolve("A"); err != nil || v != "value-A" {
		t.Fatalf("resolve after keyless changes: %v", err)
	}
}

// A damaged sealed vault, a wrong key or a missing key fails closed with a
// plain message and the file is never written over.
func TestVaultSealCorruptFailsClosed(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	good := rawVault(t, s)
	edits := map[string]func(m map[string]any){
		"bad key id":       func(m map[string]any) { m["seal"].(map[string]any)["key_id"] = "nope" },
		"bad public key":   func(m map[string]any) { m["seal"].(map[string]any)["public_key"] = "AAAA" },
		"unknown keystore": func(m map[string]any) { m["seal"].(map[string]any)["keystore"] = "floppy" },
		"no seal header":   func(m map[string]any) { delete(m, "seal") },
		"clear value": func(m map[string]any) {
			m["entries"].([]any)[0].(map[string]any)["value"] = "value-x"
		},
		"no sealed value": func(m map[string]any) {
			delete(m["entries"].([]any)[0].(map[string]any), "sealed")
		},
		"garbled value": func(m map[string]any) {
			m["entries"].([]any)[0].(map[string]any)["sealed"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
	}
	for name, edit := range edits {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		edit(m)
		b, _ := json.Marshal(m)
		if err := os.WriteFile(s.Path(), b, 0o600); err != nil {
			t.Fatal(err)
		}
		cli := OpenWith(s.Dir(), ks)
		_, errList := cli.List()
		_, _, errRes := cli.Resolve("A")
		_, errAdd := cli.Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"})
		// A garbled sealed value is found only by the key: a process without
		// it keeps it as it is (and the CLI then fails closed on it).
		var errCap error
		if name != "garbled value" {
			_, errCap = Open(s.Dir()).CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, time.Second)
		}
		if errRes == nil || errAdd == nil || (name != "garbled value" && (errList == nil || errCap == nil)) {
			t.Fatalf("%s: list=%v resolve=%v add=%v capture=%v", name, errList, errRes, errAdd, errCap)
		}
		for _, err := range []error{errList, errRes, errAdd, errCap} {
			if err != nil && strings.Contains(err.Error(), "value-") {
				t.Fatalf("%s: an error carries a value: %v", name, err)
			}
		}
		if !bytes.Equal(b, rawVault(t, s)) {
			t.Fatalf("%s: written over", name)
		}
	}
	if err := os.WriteFile(s.Path(), good, 0o600); err != nil {
		t.Fatal(err)
	}

	// The key in the keystore is another vault's.
	other := sealedStore(t, ks)
	if _, err := other.Add(AddInput{Name: "Z", Value: "value-z", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	var h struct {
		Seal sealHeader `json:"seal"`
	}
	_ = json.Unmarshal(good, &h)
	var ho struct {
		Seal sealHeader `json:"seal"`
	}
	_ = json.Unmarshal(rawVault(t, other), &ho)
	ks.mu.Lock()
	saved := ks.items[h.Seal.KeyID]
	ks.items[h.Seal.KeyID] = ks.items[ho.Seal.KeyID]
	ks.mu.Unlock()
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); !errors.Is(err, ErrDamaged) {
		t.Fatalf("wrong key: %v", err)
	}
	// The key is gone from the keystore.
	ks.mu.Lock()
	delete(ks.items, h.Seal.KeyID)
	ks.mu.Unlock()
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); !errors.Is(err, ErrKeyUnavailable) || !strings.Contains(err.Error(), "not in your macOS Keychain") {
		t.Fatalf("missing key: %v", err)
	}
	// The keystore cannot be reached (locked over SSH).
	ks.mu.Lock()
	ks.items[h.Seal.KeyID] = saved
	ks.loadErr = errors.New("the macOS keychain is locked and this session cannot ask you to unlock it")
	ks.mu.Unlock()
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); !errors.Is(err, ErrKeyUnavailable) || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked keystore: %v", err)
	}
	if !bytes.Equal(good, rawVault(t, s)) {
		t.Fatal("written over")
	}
}

// The gateway or sandbox daemon (Open) captures into a sealed vault with
// the public key alone: it never calls the keystore, it finds a value the
// vault already holds by fingerprint, and the CLI opens what it stored.
func TestVaultSealDaemonCapturesWithoutKey(t *testing.T) {
	ks := newFakeKeys()
	cli := sealedStore(t, ks)
	if _, err := cli.Add(AddInput{Name: "MY_ANTHROPIC", Value: fakeAnthropic(), Host: "api.anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	callsBefore, _ := ks.count()
	daemon := withClock(Open(cli.Dir()))
	res, err := daemon.CaptureAll([]CaptureInput{
		{Value: fakeAnthropic(), Kind: "anthropic-key", Exposed: true, From: "claudecode tool call in sandbox sb1"},
		{Value: fakeGitHub(), Kind: "github-token", From: "claudecode prompt in sandbox sb1"},
	}, CaptureWait)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Entry.Name != "MY_ANTHROPIC" || !res[0].Entry.Exposed || res[1].Entry.Name != "GITHUB_TOKEN" || !res[1].New {
		t.Fatalf("captured = %+v", res)
	}
	// The same value again is found by fingerprint, not stored twice.
	again, err := daemon.CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, CaptureWait)
	if err != nil || again[0].New || again[0].Entry.Name != "GITHUB_TOKEN" {
		t.Fatalf("again = %+v %v", again, err)
	}
	if calls, _ := ks.count(); calls != callsBefore {
		t.Fatal("the daemon called the keystore")
	}
	raw := rawVault(t, cli)
	mustNotHold(t, raw, fakeAnthropic(), fakeGitHub())
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("the daemon unsealed the vault")
	}
	// Captured entries need confirming first (metadata only: no key).
	if _, err := daemon.Confirm("GITHUB_TOKEN"); err != nil {
		t.Fatalf("the daemon could not confirm: %v", err)
	}
	if calls, _ := ks.count(); calls != callsBefore {
		t.Fatal("confirm called the keystore")
	}
	if _, _, err := daemon.Resolve("GITHUB_TOKEN"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("the daemon opened a value: %v", err)
	}
	if _, v, err := OpenWith(cli.Dir(), ks).Resolve("GITHUB_TOKEN"); err != nil || v != fakeGitHub() {
		t.Fatalf("cli resolve: %v", err)
	}
	// A file vault stays a file when the daemon writes it.
	d2 := Open(filepath.Join(t.TempDir(), "vault"))
	if _, err := d2.CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, CaptureWait); err != nil {
		t.Fatal(err)
	}
	if fileVersionOf(t, rawVault(t, d2)) != fileVersion || d2.Notice() != "" {
		t.Fatal("the daemon sealed or noted")
	}
}

// The CLI and the daemon write one sealed vault at once: every change
// lands, the vault stays sealed and every value opens.
func TestVaultSealConcurrentWriters(t *testing.T) {
	ks := newFakeKeys()
	cli := sealedStore(t, ks)
	if _, err := cli.Add(AddInput{Name: "SEED", Value: "value-seed", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	captured := func(i int) string {
		b := []byte(fakeGitHub())
		b[len(b)-1] = "ABCDEFGH"[i]
		return string(b)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 6; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, err := OpenWith(cli.Dir(), ks).Add(AddInput{Name: fmt.Sprintf("M%d", i), Value: fmt.Sprintf("value-m%d", i), Host: "api.example.com"})
			errs <- err
		}(i)
		go func(i int) {
			defer wg.Done()
			_, err := Open(cli.Dir()).CaptureAll([]CaptureInput{{Value: captured(i), Kind: "github-token"}}, 10*time.Second)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := cli.List()
	if err != nil || len(list) != 13 {
		t.Fatalf("list = %d %v", len(list), err)
	}
	raw := rawVault(t, cli)
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("not sealed")
	}
	got := map[string]bool{}
	for _, e := range list {
		if e.Source != SourceCaptured {
			continue
		}
		if _, err := OpenWith(cli.Dir(), ks).Confirm(e.Name); err != nil {
			t.Fatal(err)
		}
		_, v, err := OpenWith(cli.Dir(), ks).Resolve(e.Name)
		if err != nil {
			t.Fatal(err)
		}
		got[v] = true
	}
	for i := 0; i < 6; i++ {
		if !got[captured(i)] {
			t.Fatalf("capture %d lost", i)
		}
		mustNotHold(t, raw, captured(i), fmt.Sprintf("value-m%d", i))
	}
}

// A vault version this DefenseClaw does not know is refused.
func TestVaultSealUnknownVersionRefused(t *testing.T) {
	s := sealedStore(t, newFakeKeys())
	if err := os.MkdirAll(s.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), []byte(`{"version":3,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil || !strings.Contains(err.Error(), "version 3") {
		t.Fatalf("list = %v", err)
	}
}
