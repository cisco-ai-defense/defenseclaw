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
// to clientImages' worker and delivers the event without a digest. The first
// exec of an image the cache has not seen is therefore not identified: the
// host plane reports it as before, never the other way round.

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
// key, or "" after queueing a hash of it. It always takes ownership of file.
// account (eventAccount) bounds the exec account's queued hashes.
func (h *imageHasher) digestOf(file *os.File, key imageKey, account string) string {
	if h.off.Load() || key.size <= 0 || key.size > maxClientImageBytes || !localImageFS(file) {
		file.Close()
		return ""
	}
	h.mu.Lock()
	if element, found := h.sums[key]; found {
		h.order.MoveToFront(element)
		sum := h.digest[key]
		h.mu.Unlock()
		file.Close()
		return sum
	}
	if _, queued := h.pending[key]; queued || h.perAccount[account] >= maxClientImageJobsPerAccount {
		h.mu.Unlock()
		file.Close()
		return ""
	}
	select {
	case h.jobs <- imageJob{file: file, key: key, account: account}:
		h.pending[key] = struct{}{}
		h.perAccount[account]++
		h.busy.Add(1)
	default:
		file.Close()
	}
	h.mu.Unlock()
	h.start.Do(func() { go h.work() })
	return ""
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
		if err == nil && ok && after == job.key {
			h.remember(job.key, sum)
		}
		h.mu.Unlock()
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
