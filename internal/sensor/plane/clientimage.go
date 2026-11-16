// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The exec-time identity of an agent client image (R108-COWORK-3).
//
// The host plane tells a Claude Code client whose own arguments name an MCP
// package (a --mcp-config value, a -p prompt) from a program that starts a
// local MCP server. Only the image's identity separates the two, and the host
// plane often cannot read it: the gateway runs unprivileged while sessions run
// as other accounts (the Cowork VM), and the process has often exited before
// the event is handled (Windows reads the Security log on a poll). So the
// source, which reads the event as it happens and with the acquisition
// privilege, pins the image of an exec whose install layout names a Claude
// release and records the version that layout claims, plus the image's digest
// once it is known. The host plane only compares that pair with the signed
// release manifest: it reads no process, path or account afterwards.
//
// Hashing a release image reads a few hundred MiB, so it never runs on a
// source's reader. The reader opens the image (cheap, and it pins the file),
// looks its identity up in the digest cache, and otherwise hands the open file
// to clientImages' worker and delivers the event without a digest, marked
// pending. When the read ends the source delivers the digest in an event of
// its own (KindImageDigest) for that exec, so the host plane can wait for it
// within its hold bounds (cowork-1-0-8 GAP-0067). An exec whose digest does
// not come in time is reported as before, never the other way round.

// imageKey identifies the contents of one image file: the file (device and
// inode, or volume and file index), its size, and its change and write times
// (on Windows the file's USN, which only the file system sets, in place of the
// change time). Writing a file changes the key, so a cached digest is never
// reused for new bytes.
type imageKey struct {
	device, file           uint64
	size, changed, written int64
}

const (
	// maxClientImageBytes bounds one hash near real release sizes: native
	// Claude Code images are 200-280 MiB.
	maxClientImageBytes = 384 << 20
	// clientImageDeadline bounds one hash on a responsive file system; a
	// slower read is abandoned. A read that never returns would hold the
	// worker (identification stops, detection does not), which is why images
	// on network and FUSE file systems are never hashed on Linux and macOS,
	// nor images on remote volumes on Windows (localImageFS).
	clientImageDeadline = 20 * time.Second
	// maxClientImageDigests is the digest cache's size (one entry per
	// installed release image per account).
	maxClientImageDigests = 32
	// maxClientImageJobs bounds queued hashes; maxClientImageJobsPerAccount keeps
	// one account from taking the queue.
	maxClientImageJobs           = 4
	maxClientImageJobsPerAccount = 1
	// maxDigestWaiters bounds the execs waiting for a queued hash; past it an
	// exec's digest is reported as not coming.
	maxDigestWaiters = 64
)

type imageJob struct {
	file    *os.File
	key     imageKey
	account string
}

// imageHasher is the digest cache and its single worker.
type imageHasher struct {
	// hash reads one image; tests replace it.
	hash func(file *os.File, size int64, deadline time.Time) (string, error)
	off  atomic.Bool

	mu         sync.Mutex
	order      *list.List // of imageKey, most recent first
	sums       map[imageKey]*list.Element
	digest     map[imageKey]string
	pending    map[imageKey]struct{}
	waiters    map[imageKey][]func(sum string, ok bool)
	waiting    int
	perAccount map[string]int
	jobs       chan imageJob
	start      sync.Once
	busy       sync.WaitGroup
}

func newImageHasher() *imageHasher {
	return &imageHasher{
		hash:       hashImage,
		order:      list.New(),
		sums:       make(map[imageKey]*list.Element),
		digest:     make(map[imageKey]string),
		pending:    make(map[imageKey]struct{}),
		waiters:    make(map[imageKey][]func(string, bool)),
		perAccount: make(map[string]int),
		jobs:       make(chan imageJob, maxClientImageJobs),
	}
}

// clientImages serves every source in this process.
var clientImages = newImageHasher()

// DisableClientImageDigests stops this process's sources from hashing client
// images, for a host plane that never uses the digest (the Secure Client
// profile keeps the client's MCP arguments classified). Sources still name
// the release version.
func DisableClientImageDigests() { clientImages.off.Store(true) }

// eventAccount is the exec's account for the per-account hash budget: its
// uid, else its Windows SID, else "" (one shared slot for unattributed execs).
func eventAccount(event Event) string {
	if event.UID != nil {
		return "uid:" + strconv.Itoa(*event.UID)
	}
	if event.UserSID != "" {
		return "sid:" + event.UserSID
	}
	return ""
}

// digestOf returns the cached digest of the open image file whose identity is
// key (DigestRead), or queues a hash of it. It always takes ownership of file.
// account (eventAccount) bounds the exec account's queued hashes.
//
// While the image's hash is queued or running, a non-nil follow is called
// once it ends, from the hasher's worker, with the digest and true, or with
// false when the read failed or the file changed during it; the state is
// then DigestPending. Every other way is DigestFailed: hashing is off, the
// file is too large or not on a local file system, the queue or the
// account's slot holds another image, the waiters are full, or follow is
// nil (the caller cannot deliver a later digest; the hash is still queued,
// for the next exec of the image).
func (h *imageHasher) digestOf(
	file *os.File, key imageKey, account string, follow func(sum string, ok bool),
) (string, DigestState) {
	if h.off.Load() || key.size <= 0 || key.size > maxClientImageBytes || !localImageFS(file) {
		file.Close()
		return "", DigestFailed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if element, found := h.sums[key]; found {
		h.order.MoveToFront(element)
		file.Close()
		return h.digest[key], DigestRead
	}
	_, queued := h.pending[key]
	if queued {
		file.Close()
	} else {
		if h.perAccount[account] >= maxClientImageJobsPerAccount {
			file.Close()
			return "", DigestFailed
		}
		select {
		case h.jobs <- imageJob{file: file, key: key, account: account}:
			h.pending[key] = struct{}{}
			h.perAccount[account]++
			h.busy.Add(1)
		default:
			file.Close()
			return "", DigestFailed
		}
		h.start.Do(func() { go h.work() })
	}
	if follow == nil || h.waiting >= maxDigestWaiters {
		return "", DigestFailed
	}
	h.waiters[key] = append(h.waiters[key], follow)
	h.waiting++
	return "", DigestPending
}

func (h *imageHasher) work() {
	for job := range h.jobs {
		sum, err := h.hash(job.file, job.key.size, time.Now().Add(clientImageDeadline))
		// The file must still be the one the key named once it is read:
		// a digest of bytes written during the read is never cached.
		after, ok := statImageKey(job.file)
		job.file.Close()
		h.mu.Lock()
		delete(h.pending, job.key)
		if h.perAccount[job.account]--; h.perAccount[job.account] <= 0 {
			delete(h.perAccount, job.account)
		}
		read := err == nil && ok && after == job.key
		if read {
			h.remember(job.key, sum)
		} else {
			sum = ""
		}
		waiters := h.waiters[job.key]
		delete(h.waiters, job.key)
		h.waiting -= len(waiters)
		h.mu.Unlock()
		for _, follow := range waiters {
			follow(sum, read)
		}
		h.busy.Done()
	}
}

// remember caches a digest, evicting the least recently used. h.mu is held.
func (h *imageHasher) remember(key imageKey, sum string) {
	if element, found := h.sums[key]; found {
		h.order.MoveToFront(element)
		h.digest[key] = sum
		return
	}
	h.sums[key] = h.order.PushFront(key)
	h.digest[key] = sum
	for h.order.Len() > maxClientImageDigests {
		oldest := h.order.Back()
		h.order.Remove(oldest)
		delete(h.sums, oldest.Value.(imageKey))
		delete(h.digest, oldest.Value.(imageKey))
	}
}

// digestStateOf is the state of a source's read of an exec image that has
// no later delivery of its digest: read with a digest, failed without one,
// none for an image that is no release layout.
func digestStateOf(sum, version string) DigestState {
	switch {
	case version == "":
		return ""
	case sum != "":
		return DigestRead
	}
	return DigestFailed
}

// idle waits for the queued hashes; for tests.
func (h *imageHasher) idle() { h.busy.Wait() }

var errImageDeadline = errors.New("image hash deadline passed")

// hashImage is the hex SHA-256 of the first size bytes of file, read from its
// start; it fails on a short read or once deadline passes.
func hashImage(file *os.File, size int64, deadline time.Time) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	var read int64
	for read < size {
		if time.Now().After(deadline) {
			return "", errImageDeadline
		}
		n, err := file.Read(buffer[:min(int64(len(buffer)), size-read)])
		hash.Write(buffer[:n])
		read += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if read != size {
		return "", io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// windowsReleaseVersion is the release version a Windows ProductVersion
// names: Claude Code's claude.exe carries "2.1.312.0" for release 2.1.312.
func windowsReleaseVersion(product string) string {
	parts := strings.Split(strings.TrimSpace(product), ".")
	if len(parts) == 4 && parts[3] == "0" {
		parts = parts[:3]
	}
	return strings.Join(parts, ".")
}

// IsClaudeReleaseVersion reports a Claude Code release version: three numeric
// parts, as the native installer names its versions directory entries.
func IsClaudeReleaseVersion(version string) bool {
	parts := 0
	digits := 0
	for i := 0; i <= len(version); i++ {
		if i == len(version) || version[i] == '.' {
			if digits == 0 || digits > 8 {
				return false
			}
			parts++
			digits = 0
			continue
		}
		if version[i] < '0' || version[i] > '9' {
			return false
		}
		digits++
	}
	return parts == 3
}
