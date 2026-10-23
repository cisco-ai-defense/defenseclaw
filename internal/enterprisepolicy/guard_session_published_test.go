// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func trustAll(string) error { return nil }

// publishedSessionTestTrust names the gateway service the way a lifecycle
// does: a Windows key file lets it remove the key.
var publishedSessionTestTrust = PublishedSessionTrust{ServiceAccount: `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc}

// withPublishedSessionKeysOfTheTestAccount accepts a key file the test
// account made, where production accepts only root's, SYSTEM's or
// Administrators'. A path in refused is not a key: it stands in for a file
// another account made with a key's name.
func withPublishedSessionKeysOfTheTestAccount(t *testing.T, refused ...string) {
	t.Helper()
	restore := OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		for _, name := range refused {
			if path == name {
				return false, nil
			}
		}
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	t.Cleanup(restore)
}

// publishedSessionTestRoot is a record folder with its key, as the
// lifecycle makes it.
func publishedSessionTestRoot(t *testing.T) string {
	t.Helper()
	withoutPublishedSessionACL(t)
	withPublishedSessionKeysOfTheTestAccount(t)
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	identity := publishedSessionTestIdentity(t)
	for _, account := range []string{identity, publishedSessionOtherIdentity(identity)} {
		if err := RotatePublishedSessionKey(root, account, publishedSessionTestTrust); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// createAccountTestKey creates one more key file for identity's account
// under root (a second key when it has one).
func createAccountTestKey(root, identity string, trust PublishedSessionTrust) (string, error) {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return "", errors.New("invalid identity")
	}
	dir, prefix, ok := publishedSessionKeyPlace(root, digest)
	if !ok {
		return "", errors.New("no key place")
	}
	return createPublishedSessionKey(dir, prefix, trust)
}

// publishCurrent publishes an answer the way the gateway does: with the key
// it reads first (none when it cannot read one).
func publishCurrent(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	recordKey, _ := ReadPublishedSessionKey(root, identity)
	return PublishForeignHookSessionDecision(root, identity, key, decision, recordKey, now)
}

// publishedSessionTestAllows reports an outage allow for key.
func publishedSessionTestAllows(root, identity string, key SessionKey) bool {
	got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	return err == nil && !got.Deny
}

func publishedSessionTestKey(t *testing.T, root, identity string) SessionRecordKey {
	t.Helper()
	key, err := ReadPublishedSessionKey(root, identity)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// GAP-0352: the gateway's answer for every session exchange is written to
// the protected records, and during an outage only the records of the
// agent process and the session, under the current key, let a call go on.
func TestPublishedForeignHookSessionRecordRoundTrip(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}
	clean := GuardDecision{}
	check := func(k SessionKey, trust func(string) error) (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, k, clean, trust)
	}

	if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("no record must prove nothing: %v", err)
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("an allowed process and session must be proven unblocked: %+v %v", got, err)
	}
	reason := foreignHookBlockedPrefix + " When this agent session started, the project hook file /repo/.github/hooks/x.json defined a hook."
	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || !got.Deny || got.Reason != reason {
		t.Fatalf("a blocked process must deny with the gateway's reason: %+v %v", got, err)
	}
	// Another session of the blocked process, and the blocked session in an
	// unnamed process, are denied too.
	if got, err := check(SessionKey{Connector: "copilot", Session: "s-2", Process: key.Process}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a new session of a blocked process must deny: %+v %v", got, err)
	}
	if got, err := check(SessionKey{Connector: "copilot", Session: "s-1"}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a blocked session must deny: %+v %v", got, err)
	}
	// The allow that clears the block.
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("the clearing allow must prove the process unblocked: %+v %v", got, err)
	}
	// Another connector, another process or another account proves nothing.
	for _, other := range []SessionKey{
		{Connector: "opencode", Session: "s-1", Process: key.Process},
		{Connector: "copilot", Session: "s-1", Process: "linux:b:2:100"},
	} {
		if _, err := check(other, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%+v: a record of another key must not prove this one: %v", other, err)
		}
	}
	if _, err := CheckPublishedForeignHookSession(root, publishedSessionOtherIdentity(identity), key, clean, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("another account's record must not prove this one: %v", err)
	}
	// A record or key file that fails the trust check blocks.
	recordKey := publishedSessionTestKey(t, root, identity)
	for _, refused := range []string{"", recordKey.ID()} {
		trust := func(path string) error {
			if refused == "" || path == refused {
				return errors.New("writable by the user")
			}
			return nil
		}
		if _, err := check(key, trust); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("an untrusted record or key (%q) must prove nothing: %v", refused, err)
		}
	}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	at := time.Now().UTC().Format(time.RFC3339)
	encode := func(record PublishedSessionRecord, macIdentity string) string {
		t.Helper()
		record.MAC = publishedSessionMAC(recordKey.secret, macIdentity, record)
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	good := PublishedSessionRecord{Version: publishedSessionVersion, Connector: "copilot", Kind: sessionKindProcess, ID: key.Process, At: at}
	// The writer's own encoding of the same record proves the process: the
	// cases below differ from it in one point each.
	if err := os.WriteFile(path, []byte(encode(good, canonical)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("a well-formed record must prove the process: %+v %v", got, err)
	}
	withID, withVersion, withAt := good, good, good
	withID.ID, withVersion.Version, withAt.At = "linux:b:9:9", 2, ""
	tampered := encode(good, canonical)
	tampered = strings.Replace(tampered, `"at":"`+at+`"`, `"at":"`+time.Now().Add(time.Second).UTC().Format(time.RFC3339)+`"`, 1)
	for name, content := range map[string]string{
		"corrupt":           `{"v":3,"connector":"copilot"`,
		"unknown field":     strings.TrimSuffix(encode(good, canonical), "}") + `,"x":1}`,
		"other key":         encode(withID, canonical),
		"other version":     encode(withVersion, canonical),
		"no time":           encode(withAt, canonical),
		"no MAC":            strings.Replace(encode(good, canonical), `,"mac":"`, `,"x":"`, 1),
		"another account":   encode(good, publishedSessionOtherIdentity(canonical)),
		"a changed field":   tampered,
		"trailing value":    encode(good, canonical) + ` {}`,
		"an earlier schema": `{"v":2,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":"` + at + `","gen":"1"}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s: the record must prove nothing: %v", name, err)
		}
	}
	// Review P2: a session record alone proves nothing. An agent process the
	// hook cannot name may be one that started during the outage and
	// resumed the session ID, and a named one needs its own record.
	unnamed := SessionKey{Connector: "copilot", Session: "u-1"}
	if err := publishCurrent(root, identity, unnamed, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(unnamed, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) || got.Deny {
		t.Fatalf("an unnamed process must not be proven by a clean session record: %+v %v", got, err)
	}
	if _, err := check(SessionKey{Connector: "copilot", Session: "u-1", Process: "linux:b:3:100"}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a named process without its own record must not be proven by the session: %v", err)
	}
}

// Kill switch (1.0.4 guard loop round 1): an outage allow needs the record
// of every key part the call names. A process allowed in one session is
// not allowed in a session the gateway never answered for under the
// current key (a new one, or one whose record a block left or a removal
// ended), so a block whose publication failed for the session cannot leave
// another process's allow usable in it.
func TestPublishedForeignHookSessionNeedsTheRecordOfTheSessionToo(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	own := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-2"}
	if err := publishCurrent(root, identity, own, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, own) {
		t.Fatal("the process in its own session must be allowed")
	}
	resumed := SessionKey{Connector: "copilot", Session: "s-9", Process: own.Process}
	if publishedSessionTestAllows(root, identity, resumed) {
		t.Fatal("a session with no record must not be allowed on the process record alone")
	}
	// The session record of an earlier key is dead too.
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: resumed.Session}, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Process: own.Process}, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestAllows(root, identity, resumed) {
		t.Fatal("a session record of an earlier key must not prove the session")
	}
	// A blocking session record denies a process that is allowed elsewhere.
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: resumed.Session}, GuardDecision{Deny: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, resumed, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a blocked session must deny: %+v %v", got, err)
	}
}

// Kill switch per account: removing an account's key ends every allow of
// that account, of every connector, with no record found or deleted, and
// leaves every other account's allows alone. An allow published while the
// account has no key proves nothing, and neither does any record after a
// new key: only the next exchange under it proves the process again.
// Killing what is gone is no error. A rotation is one rename: the account
// has its new key at once, and the old allows are dead.
func TestKillPublishedSessionKeyEndsEveryEarlierAllowOfTheAccount(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	copilot := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	opencode := SessionKey{Connector: "opencode", Session: "o-1", Process: "p-1"}
	publish := func(accounts ...string) {
		t.Helper()
		for _, account := range accounts {
			for _, key := range []SessionKey{copilot, opencode} {
				if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	allowed := func(account string) int {
		count := 0
		for _, key := range []SessionKey{copilot, opencode} {
			if publishedSessionTestAllows(root, account, key) {
				count++
			}
		}
		return count
	}
	publish(identity, other)
	if allowed(identity) != 2 || allowed(other) != 2 {
		t.Fatalf("every published allow must prove its process: %d %d", allowed(identity), allowed(other))
	}
	if err := RevokePublishedSessionKey(root, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root, identity); err == nil {
		t.Fatal("no key may be left for the account")
	}
	if allowed(identity) != 0 {
		t.Fatalf("the kill must end every earlier allow of the account: %d", allowed(identity))
	}
	if allowed(other) != 2 {
		t.Fatalf("the kill must not end another account's allows: %d", allowed(other))
	}
	publish(identity)
	if allowed(identity) != 0 {
		t.Fatalf("an allow published without a key must prove nothing: %d", allowed(identity))
	}
	if err := RevokePublishedSessionKey(root, identity); err != nil {
		t.Fatalf("killing what is gone is no error: %v", err)
	}
	if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if allowed(identity) != 0 {
		t.Fatalf("a new key must not bring an earlier allow back: %d", allowed(identity))
	}
	publish(identity)
	if allowed(identity) != 2 {
		t.Fatalf("the allows of the new key must prove their processes: %d", allowed(identity))
	}
	// The rotation renames the one key: still one key, a new name, and the
	// allows of the old one are dead at once.
	before := publishedSessionTestKey(t, root, identity)
	renames := 0
	previousRename := publishedSessionRenameKey
	publishedSessionRenameKey = func(from, to string) error { renames++; return previousRename(from, to) }
	t.Cleanup(func() { publishedSessionRenameKey = previousRename })
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestKey(t, root, identity); after.ID() == before.ID() || renames != 1 {
		t.Fatalf("a rotation must rename the key once: %s -> %s (%d renames)", before.ID(), after.ID(), renames)
	}
	if allowed(identity) != 0 || allowed(other) != 2 {
		t.Fatalf("a rotation must end the account's allows only: %d %d", allowed(identity), allowed(other))
	}
	// The lifecycle removes every account's key.
	if err := KillAllPublishedSessionKeys(root); err != nil {
		t.Fatal(err)
	}
	if allowed(other) != 0 {
		t.Fatal("removing every key must end every account's allows")
	}
}

// Kill switch: any failure to rotate the key blocks. The rotation falls back
// from the rename to removing the key and making a new one, then to adding
// a second key (the hook trusts no account with two); only when all of
// that fails is the key alive (ErrPublishedSessionKeyAlive), and then the
// caller must not go on. A key folder that cannot be listed, a key owner
// that cannot be read, more than one key, or a name that is not a key's
// all block.
func TestPublishedSessionKeyRotationFailureBlocks(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	allow := func() {
		t.Helper()
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	allow()
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the allow must prove the process")
	}
	previousRename, previousRemove, previousCreate, previousMark := publishedSessionRenameKey, publishedSessionRemoveKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile
	restoreAll := func() {
		publishedSessionRenameKey, publishedSessionRemoveKey, publishedSessionCreateKeyFile, publishedSessionCreateMarkFile = previousRename, previousRemove, previousCreate, previousMark
	}
	t.Cleanup(restoreAll)
	inUse := func(op string) error {
		return &os.PathError{Op: op, Path: "key", Err: errors.New("the file is in use")}
	}
	type fault struct{ rename, remove, create, mark bool }
	for _, tc := range []struct {
		name  string
		fault fault
		alive bool
	}{
		{"rename fails, the key is removed and a new one made", fault{rename: true}, false},
		{"rename and remove fail, a second key is added", fault{rename: true, remove: true}, false},
		{"rename fails and no new key can be made", fault{rename: true, create: true}, false},
		{"rename, remove and create fail, the key is marked revoked", fault{rename: true, remove: true, create: true}, false},
		{"rename, remove, create and the mark all fail", fault{rename: true, remove: true, create: true, mark: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreAll()
			if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
				t.Fatal(err)
			}
			allow()
			if !publishedSessionTestAllows(root, identity, key) {
				t.Fatal("the allow must prove the process before the rotation")
			}
			if tc.fault.rename {
				publishedSessionRenameKey = func(string, string) error { return inUse("rename") }
			}
			if tc.fault.remove {
				publishedSessionRemoveKey = func(string) error { return inUse("remove") }
			}
			if tc.fault.create {
				publishedSessionCreateKeyFile = func(string, PublishedSessionTrust) error { return errors.New("no space left on device") }
			}
			if tc.fault.mark {
				publishedSessionCreateMarkFile = func(string) error { return errors.New("no space left on device") }
			}
			err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust)
			if got := errors.Is(err, ErrPublishedSessionKeyAlive); got != tc.alive {
				t.Fatalf("alive = %v, want %v: %v", got, tc.alive, err)
			}
			if !tc.alive && publishedSessionTestAllows(root, identity, key) {
				t.Fatal("an allow from before a rotation that ended the key must prove nothing")
			}
			if tc.fault != (fault{rename: true}) && err == nil {
				t.Fatal("a rotation that could not do it the plain way must report it")
			}
			// Allows published now prove nothing until one key is back.
			restoreAll()
			if !tc.alive && tc.fault != (fault{rename: true}) {
				allow()
				if publishedSessionTestAllows(root, identity, key) {
					t.Fatal("an allow published while the account has no single key must prove nothing")
				}
			}
			if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
				t.Fatal(err)
			}
			allow()
			if !publishedSessionTestAllows(root, identity, key) {
				t.Fatal("one key again must prove the next allow")
			}
		})
	}

	// The key folder cannot be listed: the check blocks; the rotation and
	// the revocation, which can neither rename nor remove a key they cannot
	// see, mark whatever key the account has revoked, and report the key
	// alive only when no mark can be added either. A key owner that cannot
	// be read blocks too.
	previousList := publishedSessionList
	t.Cleanup(func() { publishedSessionList = previousList })
	publishedSessionList = func(string) ([]string, error) { return nil, errors.New("input/output error") }
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key folder that cannot be listed must prove nothing")
	}
	publishedSessionCreateMarkFile = func(string) error { return errors.New("input/output error") }
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a rotation that can neither list the key folder nor add a mark must report the key alive: %v", err)
	}
	if err := RevokePublishedSessionKey(root, identity); !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a revocation that can neither list the key folder nor add a mark must report the key alive: %v", err)
	}
	publishedSessionCreateMarkFile = previousMark
	if err := RevokePublishedSessionKey(root, identity); err == nil || errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a revocation that cannot list the key folder must mark the account revoked: %v", err)
	}
	publishedSessionList = previousList
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an account marked revoked must prove nothing")
	}
	if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	allow()
	restore := OverridePublishedSessionKeyOwnerForTest(func(string) (bool, error) { return false, errors.New("access denied") })
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key owner that cannot be read must prove nothing")
	}
	restore()
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the allow under the new key must prove the process again")
	}

	// A name with the key prefix that is not a key's is no key at all.
	current := publishedSessionTestKey(t, root, identity).ID()
	dir := filepath.Dir(current)
	prefix := strings.TrimSuffix(filepath.Base(current), current[strings.LastIndex(current, PublishedSessionKeyInfix)+len(PublishedSessionKeyInfix):])
	names := []string{filepath.Join(dir, prefix+"abc")}
	if runtime.GOOS != "windows" {
		// Windows file names ignore case: there it is the key itself.
		names = append(names, filepath.Join(dir, prefix+strings.ToUpper(strings.TrimPrefix(filepath.Base(current), prefix))))
	}
	for _, name := range names {
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := publishedSessionTestKey(t, root, identity); got.ID() != current {
		t.Fatalf("a name that is not a key's must be skipped: %s", got.ID())
	}
}

// Kill switch: a file with a key's name that root, SYSTEM or
// Administrators did not make is not a key. On Windows a standard user may
// create one in %ProgramData%\Cisco: it neither counts as a second key nor
// proves anything on its own.
func TestPublishedSessionKeyOfAnotherAccountIsNoKey(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	digest, _ := publishedSessionIdentityDigest(identity)
	dir, prefix, _ := publishedSessionKeyPlace(root, digest)
	planted := filepath.Join(dir, prefix+strings.Repeat("ab", publishedSessionKeyBytes))
	if err := os.WriteFile(planted, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withPublishedSessionKeysOfTheTestAccount(t, planted)
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a planted key file must not block the real key")
	}
	if err := RevokePublishedSessionKey(root, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(planted); err != nil {
		t.Fatalf("the kill only removes keys: %v", err)
	}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, SessionRecordKey{path: planted, secret: []byte(strings.Repeat("\xab", publishedSessionKeyBytes))}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key another account made must prove nothing")
	}
}

// A repair cannot rely on replacing the record folder. An account that kept
// a way to change it (a retained Windows handle with WRITE_DAC, a macOS
// access-list entry) may put the earlier records back, folder and all,
// after the repair, and even a file with the earlier key's name. None of it
// counts: the lifecycle removed every key first, and only root or SYSTEM
// can give a file a key's name that the hook accepts.
func TestPublishedSessionRecordsPutBackAfterARepairProveNothing(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	old := publishedSessionTestKey(t, root, identity).ID()
	dir, _ := PublishedSessionIdentityDir(root, identity)
	saved := filepath.Join(t.TempDir(), "saved")
	if err := os.CopyFS(saved, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if err := KillAllPublishedSessionKeys(root); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root, identity); err != nil {
		t.Fatalf("the repair makes the account a new key: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dir, os.DirFS(saved)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withPublishedSessionKeysOfTheTestAccount(t, old)
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("records put back after a repair must prove nothing")
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the next exchange under the new key must prove the process")
	}
}

// The guardian makes sure every account folder has a key at every pass:
// none or more than one gets one new key, one is kept, and a missing record
// folder gets none.
func TestEnsurePublishedSessionKeys(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: "s", Process: "p"}, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	first := publishedSessionTestKey(t, root, identity).ID()
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil || publishedSessionTestKey(t, root, identity).ID() != first {
		t.Fatalf("one key must be kept: %v", err)
	}
	if err := RevokePublishedSessionKey(root, identity); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	second := publishedSessionTestKey(t, root, identity).ID()
	if second == first {
		t.Fatal("a missing key must be replaced by a new one")
	}
	if _, err := createAccountTestKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root, identity); err == nil {
		t.Fatal("two keys must be no key")
	}
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if third := publishedSessionTestKey(t, root, identity).ID(); third == second {
		t.Fatal("two keys must be replaced by one new one")
	}
	missing := filepath.Join(t.TempDir(), "sessions")
	if err := EnsurePublishedSessionKeys(missing, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePublishedSessionKey(missing, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, _, keys, err := accountKeys(missing, identity); err != nil || len(keys) != 0 {
		t.Fatalf("a missing record folder gets no key: %v %v", keys, err)
	}
	if err := RemovePublishedSessionKeys(root); err != nil {
		t.Fatal(err)
	}
	if _, _, keys, err := accountKeys(root, identity); err != nil || len(keys) != 0 {
		t.Fatalf("uninstall must remove every key: %v %v", keys, err)
	}
}

// Review P1 (round 3, kept): a record folder on a volume that is read-only
// proves nothing, since no key could be removed there; one whose state
// cannot be read neither. A block still denies.
func TestPublishedForeignHookSessionOnAReadOnlyVolumeProvesNothing(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if readOnly, err := publishedSessionVolumeIsReadOnly(root); err != nil || readOnly {
		t.Fatalf("a temporary folder is on a writable volume: %v %v", readOnly, err)
	}
	previous := publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionVolumeReadOnly = previous })
	for name, state := range map[string]func(string) (bool, error){
		"read-only":  func(string) (bool, error) { return true, nil },
		"unreadable": func(string) (bool, error) { return false, errors.New("statfs failed") },
	} {
		publishedSessionVolumeReadOnly = state
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%s: the allow must prove nothing", name)
		}
	}
	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a block must still deny: %+v %v", got, err)
	}
}

// The key is read again at the end of the check: a kill or a rotation
// while the check runs ends the allow it was reading.
func TestPublishedForeignHookSessionKeyKilledDuringTheCheck(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	previous := publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionVolumeReadOnly = previous })
	for name, during := range map[string]func(){
		"killed":  func() { _ = RevokePublishedSessionKey(root, identity) },
		"rotated": func() { _ = RotatePublishedSessionKey(root, identity, publishedSessionTestTrust) },
	} {
		if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
			t.Fatal(err)
		}
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		publishedSessionVolumeReadOnly = func(path string) (bool, error) {
			during()
			return false, nil
		}
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%s during the check: the allow must prove nothing", name)
		}
		publishedSessionVolumeReadOnly = previous
	}
}

// Without a root nothing is written.
func TestPublishedForeignHookSessionWithoutARootWritesNothing(t *testing.T) {
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := PublishForeignHookSessionDecision("", identity, key, GuardDecision{}, SessionRecordKey{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := PublishForeignHookSessionDecision(missing, identity, key, GuardDecision{}, SessionRecordKey{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a missing root must not be created")
	}
}

// The prune keeps the newest records within the limit.
func TestPublishedForeignHookSessionPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < publishedSessionDirLimit+5; i++ {
		path := filepath.Join(dir, "copilot-p-"+strings.Repeat("0", 3)+string(rune('a'+i%26))+strings.Repeat("x", i%7)+time.Duration(i).String()+".json")
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		mod := now.Add(-time.Duration(publishedSessionDirLimit+5-i) * time.Millisecond)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(dir, "copilot-s-old.json")
	if err := os.WriteFile(old, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := now.Add(-publishedSessionMaxAge - time.Minute)
	if err := os.Chtimes(old, stale, stale); err != nil {
		t.Fatal(err)
	}
	prunePublishedSessionRecords(dir, now)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != publishedSessionDirLimit {
		t.Fatalf("kept %d records, want %d", len(entries), publishedSessionDirLimit)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatal("a record past its age must be pruned")
	}
}

// The lifecycle's removal of every key fails closed: a key file whose
// removal fails gets a second key next to it, so the account's earlier
// allows still prove nothing; a key whose owner cannot be read is removed
// anyway (review of the consolidation: an early return left every key).
func TestKillAllPublishedSessionKeysFailsClosed(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	for _, account := range []string{identity, other} {
		if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	stuck := publishedSessionTestKey(t, root, identity).ID()
	previousRemove := publishedSessionRemoveKey
	publishedSessionRemoveKey = func(name string) error {
		if name == stuck {
			return &os.PathError{Op: "remove", Path: name, Err: errors.New("input/output error")}
		}
		return previousRemove(name)
	}
	t.Cleanup(func() { publishedSessionRemoveKey = previousRemove })
	restore := OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		if path != stuck {
			return false, errors.New("access denied")
		}
		return true, nil
	})
	err := KillAllPublishedSessionKeys(root)
	restore()
	withPublishedSessionKeysOfTheTestAccount(t)
	if err == nil {
		t.Fatal("a key that could not be removed must be reported")
	}
	if errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("the second key was added, so the key is not alive: %v", err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an account with a key that could not be removed must prove nothing (second key)")
	}
	if publishedSessionTestAllows(root, other, key) {
		t.Fatal("a key whose owner could not be read must be removed anyway")
	}
	publishedSessionRemoveKey = previousRemove
	if err := EnsurePublishedSessionKeys(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root, identity); err != nil {
		t.Fatalf("the next pass gives the account one key again: %v", err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the new key must not bring the earlier allow back")
	}
}
