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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The protected session record (GAP-0352).
//
// On a standalone host the gateway keeps each agent session's foreign-hook
// state in its private data directory (ApplyForeignHookSession). When the
// gateway is stopped, restarting or not answering and the administrator
// chose fail mode open, a guarded connector's hook must still not allow a
// session the gateway blocked: the agent may run a hook it loaded when the
// session started, even after its file was deleted. So after every session
// exchange the gateway also writes its answer for the agent process and for
// the session into a record the user can read but not change:
//
//   - Linux and macOS: <HookSessionDir>/<identity digest>/. The root
//     lifecycle creates HookSessionDir, owned by the service account (mode
//     0711). The gateway creates the per-user folder (mode 0700) with one
//     access-list entry that lets only that uid read it.
//   - Windows: %ProgramData%\Cisco\DefenseClaw-HookSessions\<digest>\. The
//     SYSTEM lifecycle creates the root; the gateway creates the per-user
//     folder with a protected DACL (SYSTEM and Administrators full, the
//     gateway service modify, that user read).
//
// One kill switch per account (1.0.4 guard consolidation). Every allow
// record carries a MAC made with its account's key. The key is the random
// name of one file next to the record folder,
// <folder name>.<account digest>.key-<64 hex>, that only root or SYSTEM
// creates; no standard user can create, rename or remove it, nor open it
// for anything a sharing mode applies to. A record whose MAC does not verify
// with the account's current key proves nothing. Every revocation ends the
// key first and only then does anything else:
//
//   - the gateway removes the account's key (RevokePublishedSessionKey: one
//     unlink, then the folder is flushed) before it records a block and
//     before it publishes any denial;
//   - the hook guardian rotates it (RotatePublishedSessionKey: one atomic
//     rename to a new random name, then the folder is flushed) under the
//     account's removal lock before it records a removal, and removes the
//     hook file only after that (ForeignHookAccountLockPaths);
//   - the lifecycle (install, upgrade, repair, ensure, uninstall), once it
//     holds the key lock (PublishedSessionKeysLockPath: its own lock on
//     Linux and macOS, LockPublishedSessionKeysForLifecycle on Windows),
//     removes every account's key before it changes anything
//     (KillAllPublishedSessionKeys); it stops
//     when it cannot show every key dead, and a run that succeeded gives
//     every account a new key as its last step
//     (RotateAllPublishedSessionKeys). The guardian makes keys at every pass
//     (EnsurePublishedSessionKeys), but only while no lifecycle run holds
//     the key lock (WithPublishedSessionKeyCreation), so no key made during
//     a run outlives it.
//
// A key that cannot be removed or renamed is revoked by a mark instead: an
// empty file <folder name>.<account digest>.revoked-<the key's 64 hex>, or
// .revoked-any-<random> when the account's keys cannot even be listed, in a
// folder every account can list and only root, SYSTEM, Administrators and
// the gateway service can add a file to (publishedSessionMarkDir). A key a
// mark names is no key, and an account with a revoked-any mark has none.
// So an earlier allow outlives a revocation only when that folder takes
// neither an unlink nor a new file (and the gateway's block, published in
// another folder, fails too). The hook does not trust that it will: during
// an outage it allows only while the mark folder still lets the gateway
// that wrote the records add a file (publishedSessionRevocable), and the
// gateway keeps a revocation that did not take owed until it takes. A
// rotation that made a new key removes the marks it listed before it
// changed anything.
//
// A new key never brings an earlier record back: its name is random, and
// no account but root or SYSTEM can give a file that name. So no revocation
// has to find the records it ends, and no account that kept a way to move
// records or folders around (a retained Windows handle, a macOS access-list
// entry) can make an earlier allow count again. A rotation that cannot end
// the key (ErrPublishedSessionKeyAlive) stops the removal before it changes
// anything: the unapproved hook stays, and the scan keeps blocking.
//
// During such an outage the hook allows a call only when all of these hold,
// and blocks otherwise:
//
//   - the account has exactly one key file that root, SYSTEM or
//     Administrators own and no revocation mark ends, and the hook's trust
//     check accepts it and every folder above it;
//   - the records of the agent process and of the session (every key part
//     the call names) say not blocked, carry a MAC that verifies with that
//     key, and are at most publishedSessionMaxAge old. A record the call
//     needs that is missing, untrusted, corrupt or dead blocks. A blocking
//     record denies with the gateway's reason, whatever its MAC;
//   - the volume of the record folder is not read-only (where no key could
//     be removed);
//   - the folder of the account's revocation marks lets the gateway that
//     wrote the records (the owner of the account's folder) add a file
//     there: it is that account's, with write and search for its owner (or
//     the gateway is root), has no immutable or append-only flag and no
//     deny entry, and is on a writable volume (publishedSessionRevocable).
//     Otherwise a block the gateway decided may have changed nothing the
//     hook reads, so no allow of the account proves anything;
//   - the key is the same at the end of the check.
//
// Any error reading the key, a record or a folder above them blocks. No
// removal state lives in this tree: the guardian's ledger is in its
// authorization folder, and the per-account removal lock in the gateway's
// data directory, which no standard user can reach.

const (
	// publishedSessionVersion is the record schema: 3 carries the MAC.
	publishedSessionVersion = 3
	// publishedSessionRecordLimit bounds one record.
	publishedSessionRecordLimit = 8 << 10
	// publishedSessionReasonLimit bounds the gateway reason a record keeps.
	publishedSessionReasonLimit = 2048
	// publishedSessionDirLimit bounds the records kept per account. A
	// record pruned past it reads as missing, which blocks.
	publishedSessionDirLimit = 1024
	// PublishedSessionKeyInfix follows the record folder's name in the name
	// of its key file.
	PublishedSessionKeyInfix = ".key-"
	// publishedSessionKeyBytes is the size of a key.
	publishedSessionKeyBytes = 32
	// publishedSessionMaxAge is the oldest answer the hook accepts during an
	// outage. The gateway writes the record again at every exchange, so an
	// agent in use keeps a fresh one; an outage that lasts longer blocks.
	publishedSessionMaxAge = 15 * time.Minute
	// publishedSessionClockSkew is how far after now the hook still accepts
	// a record's time. The gateway and the hook read the same clock, so this
	// only covers a small step back of it.
	publishedSessionClockSkew = time.Minute
	// publishedSessionKeyRemoveAttempts bounds how often a key file a
	// reader holds for a moment is removed again.
	publishedSessionKeyRemoveAttempts = 3
	// publishedSessionMarkInfix follows the account digest in the name of a
	// revocation mark; publishedSessionMarkAny starts the rest of the name of
	// a mark that ends whatever key the account has.
	publishedSessionMarkInfix = ".revoked-"
	publishedSessionMarkAny   = "any-"
)

// publishedSessionRemoveKey removes a key file, publishedSessionCreateKeyFile
// creates one, publishedSessionCreateMarkFile creates a revocation mark and
// publishedSessionList lists a folder (replaceable in tests, which stand in
// for a key file that cannot be removed or created, a mark that cannot be
// added and a folder that cannot be listed).
var (
	publishedSessionRemoveKey      = os.Remove
	publishedSessionRenameKey      = os.Rename
	publishedSessionCreateKeyFile  = createPublishedSessionKeyFile
	publishedSessionCreateMarkFile = createPublishedSessionMarkFile
	publishedSessionList           = func(dir string) ([]string, error) {
		folder, err := os.Open(dir)
		if err != nil {
			return nil, err
		}
		defer func() { _ = folder.Close() }()
		return folder.Readdirnames(-1)
	}
)

// publishedSessionKeyOwner reports whether the key file at path is a
// regular file that root, SYSTEM or Administrators own
// (publishedSessionKeyOwnerCheck). An error, other than a file that is not
// a key at all, blocks.
var (
	publishedSessionKeyOwnerMu sync.RWMutex
	publishedSessionKeyOwner   = publishedSessionKeyOwnerCheck
)

// OverridePublishedSessionKeyOwnerForTest replaces the owner check of key
// files, for tests that cannot run as root or SYSTEM.
func OverridePublishedSessionKeyOwnerForTest(check func(path string) (bool, error)) (restore func()) {
	publishedSessionKeyOwnerMu.Lock()
	previous := publishedSessionKeyOwner
	publishedSessionKeyOwner = check
	publishedSessionKeyOwnerMu.Unlock()
	return func() {
		publishedSessionKeyOwnerMu.Lock()
		publishedSessionKeyOwner = previous
		publishedSessionKeyOwnerMu.Unlock()
	}
}

// OverridePublishedSessionKeyRemoveForTest replaces the removal of key
// files, for tests in other packages that stand in for a key file the
// operating system refuses to remove.
func OverridePublishedSessionKeyRemoveForTest(remove func(path string) error) (restore func()) {
	previous := publishedSessionRemoveKey
	publishedSessionRemoveKey = remove
	return func() { publishedSessionRemoveKey = previous }
}

func publishedSessionKeyOwned(path string) (bool, error) {
	publishedSessionKeyOwnerMu.RLock()
	check := publishedSessionKeyOwner
	publishedSessionKeyOwnerMu.RUnlock()
	return check(path)
}

// publishedSessionVolumeReadOnly reports whether the volume of a path is
// mounted read-only (replaceable in tests, which cannot mount one).
var publishedSessionVolumeReadOnly = publishedSessionVolumeIsReadOnly

// publishedSessionRevocable reports why the gateway that wrote the records
// in an account folder (its owner) might not be able to revoke them now,
// nil when it can add a revocation mark: publishedSessionRevocableCheck
// (replaceable in tests).
var publishedSessionRevocable = publishedSessionRevocableCheck

// OverridePublishedSessionRevocableForTest replaces the check that the
// gateway that wrote an account's records could still revoke them, for
// tests in other packages whose test account stands in for the gateway
// service a record folder's access list names.
func OverridePublishedSessionRevocableForTest(check func(root, accountDir string) error) (restore func()) {
	previous := publishedSessionRevocable
	publishedSessionRevocable = check
	return func() { publishedSessionRevocable = previous }
}

// ErrPublishedSessionUnavailable is a protected session record that does
// not prove the session unblocked: missing, unreadable, untrusted, corrupt,
// stale or dead (its MAC does not verify with the current key).
var ErrPublishedSessionUnavailable = errors.New("protected foreign-hook session record unavailable")

// PublishedSessionRecord is the gateway's last answer for one agent process
// ("p") or session ("s") of one connector. An allow carries the MAC
// (publishedSessionMAC) made with the key that was current when the
// gateway read its inputs.
type PublishedSessionRecord struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason,omitempty"`
	At        string `json:"at"`
	MAC       string `json:"mac,omitempty"`
}

// PublishedSessionTrust names the accounts besides root/SYSTEM and
// Administrators that may own and write the protected record: the gateway
// service uid (Linux, macOS; from the root-owned runtime descriptor) or
// service account (Windows, which a key file lets remove it). A key file is
// never the service's.
type PublishedSessionTrust struct {
	ServiceUID     int
	ServiceAccount string
}

// SessionRecordKey is the key of a record folder: the key file and the
// secret its name holds. The zero value is no key: an allow published with
// it proves nothing.
type SessionRecordKey struct {
	path   string
	secret []byte
}

// ID names the key (its file); "" for no key.
func (k SessionRecordKey) ID() string { return k.path }

// IsZero reports no key.
func (k SessionRecordKey) IsZero() bool { return len(k.secret) == 0 }

// PublishedSessionIdentityDir is the folder of one account below root: the
// first 20 bytes of the SHA-256 of the canonical account identity (a
// decimal uid or an upper-case SID), the digest the gateway's private
// session store uses.
func PublishedSessionIdentityDir(root, identity string) (string, bool) {
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	root = strings.TrimSpace(root)
	if !ok || root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	return filepath.Join(filepath.Clean(root), sha256Hex([]byte(canonical))[:40]), true
}

// PublishedSessionRecordPath is the protected record of one agent process
// (kind "p") or session (kind "s") of a connector for identity under root.
func PublishedSessionRecordPath(root, identity, connectorName, kind, id string) (string, bool) {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok || !publishedSessionConnector(connectorName) || (kind != sessionKindProcess && kind != sessionKindSession) || id == "" {
		return "", false
	}
	return publishedSessionPath(dir, connectorName, kind, id), true
}

func publishedSessionPath(dir, connectorName, kind, id string) string {
	name := connectorName + "-" + kind + "-" + sha256Hex([]byte(connectorName + "\x00" + kind + "\x00" + id))[:40] + ".json"
	return filepath.Join(dir, name)
}

// publishedSessionConnector is a connector name that is safe in a record
// file name.
func publishedSessionConnector(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// PublishedSessionKeyDir is the folder the key files of the record folder
// root are in: the folder above root (on Linux and macOS the hook socket
// folder, which only root and the gateway service can change; on Windows
// %ProgramData%\Cisco, where no standard user may rename or delete a file
// another account made).
func PublishedSessionKeyDir(root string) (string, bool) {
	dir, _, ok := publishedSessionKeyRoot(root)
	return dir, ok
}

// publishedSessionKeyRoot is the key folder of root and the prefix every key
// file of root starts with: <root name>.
func publishedSessionKeyRoot(root string) (dir, prefix string, ok bool) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", "", false
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", "", false
	}
	return filepath.Dir(root), filepath.Base(root) + ".", true
}

// publishedSessionKeyPlace is the key folder of root and the prefix of the
// key file of the account whose folder name is digest (the 40 hex digits of
// PublishedSessionIdentityDir): <root name>.<digest>.key-. Each account has
// its own key, so one account's revocation never ends another's allows.
func publishedSessionKeyPlace(root, digest string) (dir, prefix string, ok bool) {
	dir, rootPrefix, ok := publishedSessionKeyRoot(root)
	if !ok || !publishedSessionDigest(digest) {
		return "", "", false
	}
	return dir, rootPrefix + digest + PublishedSessionKeyInfix, true
}

// publishedSessionDigest reports an account folder name: 40 lower-case hex.
func publishedSessionDigest(name string) bool {
	if len(name) != 40 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// publishedSessionIdentityDigest is the account folder name of identity.
func publishedSessionIdentityDigest(identity string) (string, bool) {
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	if !ok {
		return "", false
	}
	return sha256Hex([]byte(canonical))[:40], true
}

// IsPublishedSessionKeyName reports a file name that has the form of a key
// file name: <anything>.key-<64 lower-case hex>.
func IsPublishedSessionKeyName(name string) bool {
	i := strings.LastIndex(name, PublishedSessionKeyInfix)
	if i <= 0 {
		return false
	}
	_, ok := publishedSessionKeySecret(name[i+len(PublishedSessionKeyInfix):])
	return ok
}

// publishedSessionKeySecret decodes the secret of a key file name's suffix.
func publishedSessionKeySecret(suffix string) ([]byte, bool) {
	if len(suffix) != 2*publishedSessionKeyBytes || strings.ToLower(suffix) != suffix {
		return nil, false
	}
	secret, err := hex.DecodeString(suffix)
	return secret, err == nil
}

// publishedSessionKeys lists the key files with prefix in the key folder dir
// that root, SYSTEM or Administrators own. A file with the prefix that
// another account owns is not a key (on Windows a standard user may create
// one in %ProgramData%\Cisco) and is skipped; a key folder that cannot be
// listed, or a file whose owner cannot be read, is an error.
func publishedSessionKeys(dir, prefix string) ([]SessionRecordKey, error) {
	names, err := publishedSessionList(dir)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var keys []SessionRecordKey
	for _, name := range names {
		if !hasPrefixFold(name, prefix) {
			continue
		}
		secret, ok := publishedSessionKeySecret(name[len(prefix):])
		if !ok {
			continue
		}
		path := filepath.Join(dir, name)
		owned, err := publishedSessionKeyOwned(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if owned {
			keys = append(keys, SessionRecordKey{path: path, secret: secret})
		}
	}
	return keys, nil
}

// accountKeys lists the key files of identity's account under root.
func accountKeys(root, identity string) (dir, prefix string, keys []SessionRecordKey, err error) {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return "", "", nil, fmt.Errorf("invalid caller identity")
	}
	dir, prefix, ok = publishedSessionKeyPlace(root, digest)
	if !ok {
		return "", "", nil, fmt.Errorf("no protected session record folder %q", root)
	}
	keys, err = publishedSessionKeys(dir, prefix)
	return dir, prefix, keys, err
}

// ReadPublishedSessionKey is the current key of identity's account in the
// record folder root: its one key file. None, more than one, one a
// revocation mark ends, or a key or mark folder that cannot be read is an
// error; an allow published without a key proves nothing.
func ReadPublishedSessionKey(root, identity string) (SessionRecordKey, error) {
	_, _, keys, err := accountKeys(root, identity)
	if err != nil {
		return SessionRecordKey{}, err
	}
	switch len(keys) {
	case 1:
	case 0:
		return SessionRecordKey{}, fmt.Errorf("the account has no protected session record key under %s", root)
	default:
		return SessionRecordKey{}, fmt.Errorf("the account has %d protected session record keys under %s", len(keys), root)
	}
	digest, _ := publishedSessionIdentityDigest(identity)
	marks, err := publishedSessionMarksOf(root, digest)
	if err != nil {
		return SessionRecordKey{}, fmt.Errorf("the revocation marks of the account under %s cannot be read: %w", root, err)
	}
	if marks.ends(keys[0]) {
		return SessionRecordKey{}, fmt.Errorf("the account's protected session record key under %s was revoked", root)
	}
	return keys[0], nil
}

// readPublishedSessionKeyForHook is ReadPublishedSessionKey after trust
// accepted the key file and every folder above it
// (ValidatePublishedSessionPath, which also requires a root, SYSTEM or
// Administrators owner).
func readPublishedSessionKeyForHook(root, identity string, trust func(string) error) (SessionRecordKey, error) {
	key, err := ReadPublishedSessionKey(root, identity)
	if err != nil {
		return SessionRecordKey{}, err
	}
	if err := trust(key.path); err != nil {
		return SessionRecordKey{}, err
	}
	return key, nil
}

// RevokePublishedSessionKey ends every record of identity's account in the
// record folder root, so that none written before proves anything during
// an outage. It removes the account's key files and flushes the key folder
// (each removal is one unlink), and adds a revocation mark for the keys it
// could not remove, or one that ends whatever key the account has when its
// keys cannot be listed. The gateway calls it before it records a block and
// before it publishes a denial. A key folder that does not exist has no
// key. It returns nil when every key is gone, an error when a mark ends what
// is left (the hook refuses a marked key), and an error wrapping
// ErrPublishedSessionKeyAlive when neither took.
func RevokePublishedSessionKey(root, identity string) error {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("%w: invalid caller identity", ErrPublishedSessionKeyAlive)
	}
	dir, prefix, ok := publishedSessionKeyPlace(root, digest)
	if !ok {
		return fmt.Errorf("%w: no protected session record folder %q", ErrPublishedSessionKeyAlive, root)
	}
	keys, err := publishedSessionKeys(dir, prefix)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return revokePublishedSessionKeyByMark(root, digest, nil, err)
	}
	if err := removePublishedSessionKeyFiles(dir, keys); err != nil {
		return revokePublishedSessionKeyByMark(root, digest, keys, err)
	}
	return nil
}

// revokePublishedSessionKeyByMark marks keys of the account digest under
// root revoked (whatever key it has when keys is empty) after cause kept
// them from being removed or rotated.
func revokePublishedSessionKeyByMark(root, digest string, keys []SessionRecordKey, cause error) error {
	if err := markPublishedSessionKeysRevoked(root, digest, keys); err != nil {
		return fmt.Errorf("%w: %v; no revocation mark could be added either: %v", ErrPublishedSessionKeyAlive, cause, err)
	}
	return fmt.Errorf("%v; a revocation mark ends the key, so the hook refuses it", cause)
}

// publishedSessionMarkPlace is the folder the revocation marks of the
// account digest under root are in (publishedSessionMarkDir) and the
// prefix of their names: <root name>.<digest>.revoked-.
func publishedSessionMarkPlace(root, digest string) (dir, prefix string, ok bool) {
	keyDir, rootPrefix, ok := publishedSessionKeyRoot(root)
	if !ok || !publishedSessionDigest(digest) {
		return "", "", false
	}
	return publishedSessionMarkDir(filepath.Clean(strings.TrimSpace(root)), keyDir), rootPrefix + digest + publishedSessionMarkInfix, true
}

// markPublishedSessionKeysRevoked adds a revocation mark for each of keys
// of the account digest under root, or one that ends whatever key the
// account has when keys is empty, and flushes the mark folder. A mark that
// is there already is kept: one key's mark has one name.
func markPublishedSessionKeysRevoked(root, digest string, keys []SessionRecordKey) error {
	dir, prefix, ok := publishedSessionMarkPlace(root, digest)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	var names []string
	for _, key := range keys {
		names = append(names, prefix+hex.EncodeToString(key.secret))
	}
	if len(names) == 0 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		names = append(names, prefix+publishedSessionMarkAny+hex.EncodeToString(nonce[:]))
	}
	var errs []error
	for _, name := range names {
		if err := publishedSessionCreateMarkFile(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrExist) {
			errs = append(errs, fmt.Errorf("add the revocation mark %s: %w", filepath.Join(dir, name), err))
		}
	}
	if len(errs) == 0 {
		if err := publishedSessionSyncDir(dir); err != nil {
			errs = append(errs, fmt.Errorf("flush %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// createPublishedSessionMarkFile creates an empty revocation mark at path,
// which must not exist (fs.ErrExist when it does), and flushes it. It gets
// the mark folder's access: only accounts that may add a file there can
// remove it.
func createPublishedSessionMarkFile(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

// publishedSessionMarkSet is the revocation marks of one account: the
// folder and names of their files, the keys they end (each key's 64 hex),
// and whether one ends whatever key the account has.
type publishedSessionMarkSet struct {
	dir   string
	names []string
	keys  map[string]bool
	any   bool
}

// ends reports a key a mark revokes.
func (m publishedSessionMarkSet) ends(key SessionRecordKey) bool {
	return m.any || m.keys[hex.EncodeToString(key.secret)]
}

// clear removes the marks listed: the caller ended every key they can name
// since. A mark added after the listing stays. One that cannot be removed
// keeps the account's outage allows blocked until a later pass.
func (m publishedSessionMarkSet) clear() {
	for _, name := range m.names {
		_ = os.Remove(filepath.Join(m.dir, name))
	}
}

// publishedSessionMarksOf lists the revocation marks of the account digest
// under root. A mark folder that does not exist holds none; one that cannot
// be listed is an error. A file with the marks' prefix whose rest names no
// key ends every key.
func publishedSessionMarksOf(root, digest string) (publishedSessionMarkSet, error) {
	dir, prefix, ok := publishedSessionMarkPlace(root, digest)
	if !ok {
		return publishedSessionMarkSet{}, fmt.Errorf("no protected session record folder %q", root)
	}
	marks := publishedSessionMarkSet{dir: dir}
	names, err := publishedSessionList(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return marks, nil
	}
	if err != nil {
		return marks, err
	}
	for _, name := range names {
		if !hasPrefixFold(name, prefix) {
			continue
		}
		marks.names = append(marks.names, name)
		rest := strings.ToLower(name[len(prefix):])
		if _, ok := publishedSessionKeySecret(rest); ok {
			if marks.keys == nil {
				marks.keys = map[string]bool{}
			}
			marks.keys[rest] = true
			continue
		}
		marks.any = true
	}
	return marks, nil
}

// isPublishedSessionMarkName reports a revocation mark of the record folder
// whose key prefix is rootPrefix.
func isPublishedSessionMarkName(name, rootPrefix string) bool {
	return hasPrefixFold(name, rootPrefix) && strings.Contains(strings.ToLower(name[len(rootPrefix):]), publishedSessionMarkInfix)
}

// removePublishedSessionKeyFiles unlinks keys, each a few times when a
// reader holds it for a moment, and flushes dir once.
func removePublishedSessionKeyFiles(dir string, keys []SessionRecordKey) error {
	var errs []error
	for _, key := range keys {
		for attempt := 1; ; attempt++ {
			err := publishedSessionRemoveKey(key.path)
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				break
			}
			if attempt == publishedSessionKeyRemoveAttempts {
				errs = append(errs, fmt.Errorf("remove the protected session record key %s: %w", key.path, err))
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(keys) != 0 {
		if err := publishedSessionSyncDir(dir); err != nil {
			errs = append(errs, fmt.Errorf("flush %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// ErrPublishedSessionKeyAlive is a revocation or rotation that could
// neither rename, nor remove, nor shadow, nor mark revoked the account's
// key, or could not list it: a record written under it may still prove an
// allow during an outage. The caller must not go on with what the
// revocation was for.
var ErrPublishedSessionKeyAlive = errors.New("the protected session record key could not be rotated, removed or marked revoked")

// RotatePublishedSessionKey ends every record of identity's account under
// root (root or SYSTEM only) and leaves the account one new key, in this
// order:
//
//  1. When the account has exactly one key, it is renamed to a fresh random
//     name in one atomic rename, and the key folder is flushed: from that
//     moment no earlier record proves anything, and the account already has
//     its new key.
//  2. Otherwise, or when the rename fails, a new key file is created first,
//     then every old key file of the account is removed and the folder
//     flushed. Until the old ones are gone the account has two or more
//     keys, which the hook refuses, so a removal that fails never leaves an
//     old key alone; without a new key, an account that has two or more
//     keys keeps them.
//  3. When one old key could be neither renamed nor removed and no new key
//     made, it is marked revoked.
//
// The revocation marks it listed before it changed anything are removed
// once every key they can name is gone. When none of that took, the error
// wraps ErrPublishedSessionKeyAlive. A rotation that ended the old key but
// could not make a new one returns an error without it: guarded calls of
// the account then block during an outage until a later pass makes a key.
func RotatePublishedSessionKey(root, identity string, trust PublishedSessionTrust) error {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("%w: invalid caller identity", ErrPublishedSessionKeyAlive)
	}
	return rotatePublishedSessionAccountKey(root, digest, trust)
}

func rotatePublishedSessionAccountKey(root, digest string, trust PublishedSessionTrust) error {
	dir, prefix, ok := publishedSessionKeyPlace(root, digest)
	if !ok {
		return fmt.Errorf("%w: no protected session record folder %q", ErrPublishedSessionKeyAlive, root)
	}
	// The marks before any key changes: only these are removed once the
	// keys they name are gone; one a revocation adds meanwhile stays.
	marks, marksErr := publishedSessionMarksOf(root, digest)
	clearMarks := func() {
		if marksErr == nil {
			marks.clear()
		}
	}
	keys, err := publishedSessionKeys(dir, prefix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return revokePublishedSessionKeyByMark(root, digest, nil, err)
	}
	if len(keys) == 1 {
		next, nameErr := newPublishedSessionKeyName(dir, prefix)
		if nameErr == nil {
			if renameErr := publishedSessionRenameKey(keys[0].path, next); renameErr == nil {
				if syncErr := publishedSessionSyncDir(dir); syncErr != nil {
					return fmt.Errorf("flush %s after the key rotation: %w", dir, syncErr)
				}
				clearMarks()
				return nil
			}
		}
	}
	if err := publishedSessionRecordRootExists(root); err != nil {
		// Without a record folder there is no record to end and no key to
		// make; a key file left over is removed, or else marked revoked.
		if killErr := removePublishedSessionKeyFiles(dir, keys); killErr != nil {
			return revokePublishedSessionKeyByMark(root, digest, keys, killErr)
		}
		return nil
	}
	_, createErr := createPublishedSessionKey(dir, prefix, trust)
	if createErr != nil && len(keys) >= 2 {
		return fmt.Errorf("no new key could be made (%v); the account keeps its %d keys, which the hook refuses", createErr, len(keys))
	}
	killErr := removePublishedSessionKeyFiles(dir, keys)
	switch {
	case killErr == nil && createErr == nil:
		clearMarks()
		return nil
	case killErr == nil:
		clearMarks()
		return fmt.Errorf("the old key is gone, but no new one could be made, so the account's guarded calls block during a gateway outage until a later pass makes one: %w", createErr)
	case createErr == nil:
		return fmt.Errorf("%v; the new key stays next to it, so the hook trusts neither until a later pass removes the old one", killErr)
	}
	return revokePublishedSessionKeyByMark(root, digest, keys, fmt.Errorf("%v; no new key could be made either: %v", killErr, createErr))
}

// publishedSessionRecordRootExists reports a record folder root that is a
// real folder.
func publishedSessionRecordRootExists(root string) error {
	info, err := os.Lstat(strings.TrimSpace(root))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a folder", root)
	}
	return nil
}

// EnsurePublishedSessionKey gives identity's account one key no revocation
// mark ends when it has none, more than one, or a revoked one
// (RotatePublishedSessionKey). A new key never makes an earlier record
// count, so this is safe at any time.
func EnsurePublishedSessionKey(root, identity string, trust PublishedSessionTrust) error {
	if err := publishedSessionRecordRootExists(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	return ensurePublishedSessionAccountKey(root, digest, trust)
}

// ensurePublishedSessionAccountKey keeps the one key of the account digest
// that no mark ends, and removes the marks of keys it no longer has;
// otherwise it rotates the account's key.
func ensurePublishedSessionAccountKey(root, digest string, trust PublishedSessionTrust) error {
	dir, prefix, ok := publishedSessionKeyPlace(root, digest)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if keys, err := publishedSessionKeys(dir, prefix); err == nil && len(keys) == 1 {
		if marks, err := publishedSessionMarksOf(root, digest); err == nil && !marks.ends(keys[0]) {
			// Every mark listed names a key that is gone, and no account
			// but root or SYSTEM makes a key with that name again.
			marks.clear()
			return nil
		}
	}
	return rotatePublishedSessionAccountKey(root, digest, trust)
}

// EnsurePublishedSessionKeys gives every account that has a folder under
// root exactly one key no revocation mark ends (root or SYSTEM only): the
// gateway removes an account's key before every block, and a lifecycle run
// removes all of them. The hook guardian runs it at every pass, while no
// lifecycle run holds the key lock (WithPublishedSessionKeyCreation).
func EnsurePublishedSessionKeys(root string, trust PublishedSessionTrust) error {
	return forEachPublishedSessionAccount(root, func(digest string) error {
		return ensurePublishedSessionAccountKey(root, digest, trust)
	})
}

// RotateAllPublishedSessionKeys gives every account that has a folder under
// root one new key, whatever key it had (root or SYSTEM only): the last
// step of a lifecycle run that succeeded, so that no allow published while
// the run changed the deployment, under a key another process made
// meanwhile, proves anything after the run.
func RotateAllPublishedSessionKeys(root string, trust PublishedSessionTrust) error {
	return forEachPublishedSessionAccount(root, func(digest string) error {
		return rotatePublishedSessionAccountKey(root, digest, trust)
	})
}

// forEachPublishedSessionAccount runs do for every account folder under
// root. A record folder that does not exist has none.
func forEachPublishedSessionAccount(root string, do func(digest string) error) error {
	names, err := publishedSessionList(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, _, ok := publishedSessionKeyRoot(root); !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	var errs []error
	for _, name := range names {
		if !publishedSessionDigest(name) {
			continue
		}
		if err := do(name); err != nil {
			errs = append(errs, fmt.Errorf("account folder %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// KillAllPublishedSessionKeys removes the key of every account under the
// record folder root (root or SYSTEM): the lifecycle runs it, holding its
// lock and the key lock, before install, upgrade, repair, ensure and
// uninstall change anything, so nothing another account did to the record
// folders while they were loosened brings an allow back. Keys come back per
// account at the end of a run that succeeded
// (RotateAllPublishedSessionKeys). A key file whose owner cannot be read is
// removed too. Each account gets a second key before its keys are removed
// (removed again after them), so a key that cannot be removed is never left
// alone: it stays next to the second key, which the hook refuses, or, when
// no second key could be made, it is marked revoked; the error names it. The error wraps ErrPublishedSessionKeyAlive when a
// key could not be shown dead: the key folder cannot be listed, or a key
// could be neither removed, nor shadowed, nor marked revoked.
func KillAllPublishedSessionKeys(root string) error {
	dir, rootPrefix, ok := publishedSessionKeyRoot(root)
	if !ok {
		return fmt.Errorf("%w: no protected session record folder %q", ErrPublishedSessionKeyAlive, root)
	}
	names, err := publishedSessionList(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: list %s: %v", ErrPublishedSessionKeyAlive, dir, err)
	}
	var prefixes []string
	accounts := map[string][]SessionRecordKey{}
	for _, name := range names {
		if !hasPrefixFold(name, rootPrefix) || !IsPublishedSessionKeyName(name) {
			continue
		}
		path := filepath.Join(dir, name)
		if owned, err := publishedSessionKeyOwned(path); err == nil && !owned {
			continue
		}
		cut := strings.LastIndex(name, PublishedSessionKeyInfix) + len(PublishedSessionKeyInfix)
		secret, _ := publishedSessionKeySecret(name[cut:])
		prefix := name[:cut]
		if _, seen := accounts[prefix]; !seen {
			prefixes = append(prefixes, prefix)
		}
		accounts[prefix] = append(accounts[prefix], SessionRecordKey{path: path, secret: secret})
	}
	var errs []error
	for _, prefix := range prefixes {
		keys := accounts[prefix]
		// A second key first: until every old key is gone the account has
		// two or more, which the hook refuses, so a removal that fails never
		// leaves an old key alone. It goes again once they are gone.
		decoy, decoyErr := createPublishedSessionKey(dir, prefix, PublishedSessionTrust{})
		if decoy == "" && len(keys) >= 2 {
			// Already refused for its keys; removing some could leave one
			// of them alone.
			errs = append(errs, fmt.Errorf("no second key could be made (%v); the account keeps its %d keys, which the hook refuses", decoyErr, len(keys)))
			continue
		}
		killErr := removePublishedSessionKeyFiles(dir, keys)
		if killErr == nil {
			if decoy != "" {
				if err := removePublishedSessionKeyFiles(dir, []SessionRecordKey{{path: decoy}}); err != nil {
					errs = append(errs, fmt.Errorf("the old keys are gone, but the second key made before their removal stays: %v", err))
				}
			}
			continue
		}
		left := publishedSessionKeysLeft(keys)
		if decoy != "" && len(left) >= 1 {
			errs = append(errs, fmt.Errorf("%v; a second key stays next to it, so the hook trusts neither", killErr))
			continue
		}
		if len(left) >= 2 {
			errs = append(errs, fmt.Errorf("%v; the account keeps %d keys, which the hook refuses", killErr, len(left)))
			continue
		}
		digest := strings.TrimSuffix(strings.ToLower(prefix[len(rootPrefix):]), PublishedSessionKeyInfix)
		if !publishedSessionDigest(digest) {
			errs = append(errs, fmt.Errorf("%w: %v", ErrPublishedSessionKeyAlive, killErr))
			continue
		}
		errs = append(errs, revokePublishedSessionKeyByMark(root, digest, keys, killErr))
	}
	return errors.Join(errs...)
}

// publishedSessionKeysLeft are the keys whose file is still there, or
// cannot be checked.
func publishedSessionKeysLeft(keys []SessionRecordKey) []SessionRecordKey {
	var left []SessionRecordKey
	for _, key := range keys {
		if _, err := os.Lstat(key.path); !errors.Is(err, fs.ErrNotExist) {
			left = append(left, key)
		}
	}
	return left
}

// RemovePublishedSessionKeys removes every key file of the record folder
// root, every file with its key prefix this account may remove, and its
// revocation marks: for uninstall, which removes the folder.
func RemovePublishedSessionKeys(root string) error {
	if err := KillAllPublishedSessionKeys(root); err != nil {
		return err
	}
	dir, rootPrefix, _ := publishedSessionKeyRoot(root)
	for _, folder := range []string{dir, publishedSessionMarkDir(filepath.Clean(strings.TrimSpace(root)), dir)} {
		names, err := publishedSessionList(folder)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, name := range names {
			if hasPrefixFold(name, rootPrefix) && (IsPublishedSessionKeyName(name) || isPublishedSessionMarkName(name, rootPrefix)) {
				_ = os.Remove(filepath.Join(folder, name))
			}
		}
	}
	return nil
}

// newPublishedSessionKeyName is a fresh random key file path with prefix in
// dir.
func newPublishedSessionKeyName(dir, prefix string) (string, error) {
	var secret [publishedSessionKeyBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, prefix+hex.EncodeToString(secret[:])), nil
}

// createPublishedSessionKey creates one key file with prefix in dir with a
// fresh random name (createPublishedSessionKeyFile: the name appears at
// once, in one create that fails when it exists) and flushes the key folder.
func createPublishedSessionKey(dir, prefix string, trust PublishedSessionTrust) (string, error) {
	path, err := newPublishedSessionKeyName(dir, prefix)
	if err != nil {
		return "", err
	}
	if err := publishedSessionCreateKeyFile(path, trust); err != nil {
		return "", fmt.Errorf("create the protected session record key %s: %w", path, err)
	}
	if err := publishedSessionSyncDir(dir); err != nil {
		return path, fmt.Errorf("flush %s: %w", dir, err)
	}
	return path, nil
}

// publishedSessionMAC is the MAC of record for the account identity
// (canonical) with secret: HMAC-SHA256 over every field, each with its
// length.
func publishedSessionMAC(secret []byte, identity string, record PublishedSessionRecord) string {
	mac := hmac.New(sha256.New, secret)
	for _, field := range []string{
		"defenseclaw protected foreign-hook session record", strconv.Itoa(record.Version), identity,
		record.Connector, record.Kind, record.ID, strconv.FormatBool(record.Blocked), record.Reason, record.At,
	} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// publishedSessionMACValid reports a record whose MAC verifies with key.
func publishedSessionMACValid(key SessionRecordKey, identity string, record PublishedSessionRecord) bool {
	if key.IsZero() || record.MAC == "" {
		return false
	}
	want := publishedSessionMAC(key.secret, identity, record)
	return hmac.Equal([]byte(want), []byte(record.MAC))
}

// PublishForeignHookSessionDecision writes the gateway's answer for one
// session exchange into the protected records of identity under root: a
// denial records the agent process and the session as blocked, an allow
// records them as not blocked, with a MAC made with recordKey, the key the
// gateway read before it read the guardian's removals
// (ReadPublishedSessionKey). An allow without a key proves nothing. A
// denial needs no MAC: the gateway removed the key before it (an earlier
// allow is dead), and a blocking record denies whatever its MAC. root
// missing is not an error: the hook then finds no record and blocks during
// an outage.
func PublishForeignHookSessionDecision(root, identity string, key SessionKey, decision GuardDecision, recordKey SessionRecordKey, now time.Time) error {
	if strings.TrimSpace(root) == "" {
		return nil
	}
	name := strings.TrimSpace(key.Connector)
	if !key.valid() || !publishedSessionConnector(name) {
		return fmt.Errorf("invalid session key")
	}
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	if err := publishedSessionPrepare(root, dir, canonical); err != nil {
		// A folder that is not ours is not written to.
		return err
	}
	if now.IsZero() {
		now = time.Now()
	}
	var errs []error
	created := false
	for _, entry := range publishedSessionAnswer(dir, canonical, name, key, decision, recordKey, now) {
		if _, err := os.Lstat(entry.path); errors.Is(err, fs.ErrNotExist) {
			created = true
		}
		if err := writePublishedSessionRecord(entry.path, entry.record); err != nil {
			errs = append(errs, err)
		}
	}
	if created {
		prunePublishedSessionRecords(dir, now)
	}
	return errors.Join(errs...)
}

// publishedSessionEntry is one record of an answer and where it goes.
type publishedSessionEntry struct {
	path   string
	record PublishedSessionRecord
}

// publishedSessionAnswer is the records of one answer of the gateway for
// key in the account folder dir of the account canonical: a denial blocks,
// with no MAC, and an allow carries the MAC made with recordKey (none
// without a key).
func publishedSessionAnswer(dir, canonical, name string, key SessionKey, decision GuardDecision, recordKey SessionRecordKey, now time.Time) []publishedSessionEntry {
	record := PublishedSessionRecord{
		Version:   publishedSessionVersion,
		Connector: name,
		Blocked:   decision.Deny,
		At:        now.UTC().Format(time.RFC3339),
	}
	if decision.Deny {
		record.Reason = clipPublishedReason(decision.Reason)
	}
	var entries []publishedSessionEntry
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		record.Kind, record.ID, record.MAC = entry.kind, entry.id, ""
		if !decision.Deny && !recordKey.IsZero() {
			record.MAC = publishedSessionMAC(recordKey.secret, canonical, record)
		}
		entries = append(entries, publishedSessionEntry{publishedSessionPath(dir, name, entry.kind, entry.id), record})
	}
	return entries
}

// WritePublishedSessionRecordsForTest writes the records the gateway
// publishes for one answer, with the record folder's current key (none when
// it has none), into an account folder it creates without the gateway's
// access list: for tests in other packages, which cannot run as the gateway
// service or give an access-list entry.
func WritePublishedSessionRecordsForTest(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	name := strings.TrimSpace(key.Connector)
	if !ok || !key.valid() || !publishedSessionConnector(name) {
		return errors.New("invalid account or session key")
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	recordKey, _ := ReadPublishedSessionKey(root, identity)
	var errs []error
	for _, entry := range publishedSessionAnswer(dir, canonical, name, key, decision, recordKey, now) {
		errs = append(errs, writePublishedSessionRecord(entry.path, entry.record))
	}
	return errors.Join(errs...)
}

// CheckPublishedForeignHookSession decides a guarded call during a gateway
// outage from the protected records of identity under root. It returns the
// scan's decision when the records of the agent process and of the session
// (each the call names) are trusted, not blocked, fresh, and carry a MAC
// that verifies with the record folder's one key, the volume is not
// read-only, and the gateway that wrote them could still revoke them
// (publishedSessionRevocable); a denial with the gateway's reason when a record blocks it;
// and ErrPublishedSessionUnavailable otherwise. An agent process the hook
// cannot name is never proven: it may be one that started during the
// outage and resumed the session ID. trust checks a record or key file path
// and every folder above it (ValidatePublishedSessionPath in production).
func CheckPublishedForeignHookSession(root, identity string, key SessionKey, decision GuardDecision, trust func(path string) error) (GuardDecision, error) {
	name := strings.TrimSpace(key.Connector)
	dir, ok := PublishedSessionIdentityDir(root, identity)
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	if !ok || !key.valid() || !publishedSessionConnector(name) || trust == nil {
		return decision, ErrPublishedSessionUnavailable
	}
	// The key first: a record read after it was written under it or under
	// an earlier one.
	recordKey, err := readPublishedSessionKeyForHook(root, identity, trust)
	if err != nil {
		return decision, fmt.Errorf("%w: the record folder's key: %v", ErrPublishedSessionUnavailable, err)
	}
	now := time.Now()
	var allows []PublishedSessionRecord
	missing := key.Process == ""
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		path := publishedSessionPath(dir, name, entry.kind, entry.id)
		record, exists, err := readPublishedSessionRecord(path, trust)
		if err != nil {
			return decision, fmt.Errorf("%w: %v", ErrPublishedSessionUnavailable, err)
		}
		if !exists {
			missing = true
			continue
		}
		if record.Version != publishedSessionVersion || record.Connector != name || record.Kind != entry.kind || record.ID != entry.id {
			return decision, fmt.Errorf("%w: %s does not belong to this agent session", ErrPublishedSessionUnavailable, path)
		}
		if record.Blocked {
			return publishedBlockDecision(decision, name, record), nil
		}
		allows = append(allows, record)
	}
	if missing {
		return decision, fmt.Errorf("%w: no record proves this agent process and session", ErrPublishedSessionUnavailable)
	}
	for _, record := range allows {
		at, err := time.Parse(time.RFC3339, record.At)
		if err != nil || !publishedSessionAgeFresh(now.Sub(at)) {
			return decision, fmt.Errorf("%w: the %s record is stale or has no valid time", ErrPublishedSessionUnavailable, record.Kind)
		}
		if !publishedSessionMACValid(recordKey, canonical, record) {
			return decision, fmt.Errorf("%w: the %s record was not written under the record folder's current key", ErrPublishedSessionUnavailable, record.Kind)
		}
	}
	// A record folder on a volume that is read-only proves nothing: no key
	// could be removed there.
	if readOnly, err := publishedSessionVolumeReadOnly(root); err != nil || readOnly {
		return decision, fmt.Errorf("%w: the record folder's volume is read-only, or its state cannot be read: %v", ErrPublishedSessionUnavailable, err)
	}
	// An allow passes an outage only while the gateway that wrote it could
	// still end it: when the folder its revocation marks go in no longer
	// lets that gateway add a file, a block it decided since may have
	// changed nothing on disk, so no allow of the account proves anything
	// (any doubt blocks).
	if err := publishedSessionRevocable(root, dir); err != nil {
		return decision, fmt.Errorf("%w: a revocation of the account's records might not take: %v", ErrPublishedSessionUnavailable, err)
	}
	// Last, the key again: one removed while this check ran ends the allow.
	if again, err := readPublishedSessionKeyForHook(root, identity, trust); err != nil || again.ID() != recordKey.ID() {
		return decision, fmt.Errorf("%w: the record folder's key changed while the record was checked", ErrPublishedSessionUnavailable)
	}
	return decision, nil
}

// publishedSessionAgeFresh reports an age within publishedSessionMaxAge
// that is not in the future by more than publishedSessionClockSkew: an
// answer dated ahead (the clock was ahead when the gateway wrote it, and
// was set back since) would otherwise stay fresh for as much longer than
// the limit.
func publishedSessionAgeFresh(age time.Duration) bool {
	return age >= -publishedSessionClockSkew && age <= publishedSessionMaxAge
}

// publishedBlockDecision denies a call the gateway's record blocks, with the
// gateway's own reason when it kept one.
func publishedBlockDecision(decision GuardDecision, connectorName string, record PublishedSessionRecord) GuardDecision {
	reason := strings.TrimSpace(record.Reason)
	if !strings.HasPrefix(reason, foreignHookBlockedPrefix) {
		reason = foreignHookBlockedPrefix + " the DefenseClaw gateway blocked this agent session's " + connectorName +
			" tool calls, and it is not running to clear the block. Retry when the DefenseClaw gateway is running; if the block continues, remove any unapproved hook and restart the agent."
	}
	decision.Deny = true
	decision.Reason = reason
	decision.Findings = append([]Finding{{
		Connector: connectorName,
		Reason:    "blocked by the gateway's protected session record",
	}}, decision.Findings...)
	return decision
}

// foreignHookBlockedPrefix starts every foreign-hook block reason
// (hookexec.ForeignHookBlockedReasonPrefix).
const foreignHookBlockedPrefix = "enterprise_foreign_hook_blocked:"

func clipPublishedReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(reason))
	if len(reason) <= publishedSessionReasonLimit {
		return reason
	}
	cut := publishedSessionReasonLimit
	for cut > 0 && (reason[cut]&0xc0) == 0x80 {
		cut--
	}
	return reason[:cut]
}

// readPublishedSessionRecord reads one record after trust accepted it and
// every folder above it. A missing record does not exist; anything else
// that cannot be checked, read or decoded is an error.
func readPublishedSessionRecord(path string, trust func(string) error) (PublishedSessionRecord, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return PublishedSessionRecord{}, false, nil
	} else if err != nil {
		return PublishedSessionRecord{}, true, err
	}
	if err := trust(path); err != nil {
		return PublishedSessionRecord{}, true, err
	}
	data, exists, err := readGuardFileLimit(path, publishedSessionRecordLimit)
	if err != nil {
		return PublishedSessionRecord{}, true, err
	}
	if !exists {
		return PublishedSessionRecord{}, false, nil
	}
	var record PublishedSessionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return PublishedSessionRecord{}, true, fmt.Errorf("%s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublishedSessionRecord{}, true, fmt.Errorf("%s: trailing content", path)
	}
	return record, true, nil
}

// writePublishedSessionRecord replaces one record atomically in its folder.
func writePublishedSessionRecord(path string, record PublishedSessionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > publishedSessionRecordLimit {
		return fmt.Errorf("session record too large")
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := publishedSessionFileMode(tmp); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	// A hook that is reading the record holds it open; on Windows that
	// refuses the replace for a moment.
	for attempt := 0; ; attempt++ {
		err := os.Rename(name, path)
		if err == nil {
			return nil
		}
		if attempt == 4 {
			_ = os.Remove(name)
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// prunePublishedSessionRecords removes records older than
// publishedSessionMaxAge or dated after now (publishedSessionAgeFresh) and,
// past publishedSessionDirLimit, the oldest ones, plus temporary files a
// crashed writer left. A pruned record reads as missing, which blocks.
func prunePublishedSessionRecords(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type aged struct {
		path string
		mod  time.Time
	}
	var kept []aged
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if strings.HasPrefix(entry.Name(), ".") {
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			continue
		}
		if !publishedSessionAgeFresh(now.Sub(info.ModTime())) {
			_ = os.Remove(path)
			continue
		}
		kept = append(kept, aged{path, info.ModTime()})
	}
	if len(kept) <= publishedSessionDirLimit {
		return
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, entry := range kept[:len(kept)-publishedSessionDirLimit] {
		_ = os.Remove(entry.path)
	}
}

// hasPrefixFold reports whether name starts with prefix, ignoring case (the
// Windows file system does).
func hasPrefixFold(name, prefix string) bool {
	return len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
}

// ForeignHookSessionStoreDir is the gateway's private session store of one
// caller identity under its data directory: the first 20 bytes of the
// SHA-256 of the identity (canonical when it is a uid or a SID), the folder
// the gateway has kept the account's session records in since 1.0.3. No
// standard user can reach it.
func ForeignHookSessionStoreDir(dataDir, identity string) string {
	if canonical, ok := connector.CanonicalUserScopedIdentity(identity); ok {
		identity = canonical
	}
	return filepath.Join(dataDir, sessionDirName, sha256Hex([]byte(identity))[:40])
}
