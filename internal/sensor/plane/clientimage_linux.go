// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// procImage is the image /proc/<pid>/exe names now: its path and the
// identity of the executing file. ok is false once the process is gone.
func procImage(pid int) (path string, key imageKey, ok bool) {
	if pid <= 0 {
		return "", imageKey{}, false
	}
	proc := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	target, err := os.Readlink(proc)
	if err != nil {
		return "", imageKey{}, false
	}
	info, err := os.Stat(proc)
	if err != nil {
		return "", imageKey{}, false
	}
	key, ok = linuxImageKey(info)
	return strings.TrimSuffix(target, " (deleted)"), key, ok
}

func linuxImageKey(info os.FileInfo) (imageKey, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return imageKey{}, false
	}
	return imageKey{
		device: stat.Dev, file: stat.Ino, size: stat.Size,
		changed: stat.Ctim.Nano(), written: stat.Mtim.Nano(),
	}, true
}

// statImageKey is the identity of an open image file.
func statImageKey(file *os.File) (imageKey, bool) {
	info, err := file.Stat()
	if err != nil {
		return imageKey{}, false
	}
	return linuxImageKey(info)
}

// pinProcImage opens the running image of pid through /proc/<pid>/exe, which
// names the executing inode: a file renamed or written over the install path
// afterwards is not what is read. It returns nil unless the opened file is
// key, the image the caller's snapshot named.
func pinProcImage(pid int, key imageKey) *os.File {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return nil
	}
	if opened, ok := statImageKey(file); !ok || opened != key {
		file.Close()
		return nil
	}
	return file
}

// tetragonClientImage is the image identity of a Tetragon exec of binary:
// pinned only while the pid still runs that binary, before and after the
// open. The digest is the cached one, or "" while clientImages hashes it
// (state pending: delivery gets the digest) or when it is not coming
// (failed).
func tetragonClientImage(
	pid int, binary string, account string, delivery *digestDelivery,
) (sum, version string, state DigestState) {
	path, key, live := procImage(pid)
	if !live || path != binary {
		return "", "", ""
	}
	if version = claudeImageVersion(path); version == "" {
		return "", "", ""
	}
	file := pinProcImage(pid, key)
	if file == nil {
		return "", version, DigestFailed
	}
	if afterPath, afterKey, afterLive := procImage(pid); !afterLive || afterPath != path || afterKey != key {
		file.Close()
		return "", version, DigestFailed
	}
	var follow func(string, bool)
	if delivery != nil {
		delivery.version, follow = version, delivery.follow
	}
	sum, state = clientImages.digestOf(file, key, account, follow)
	return sum, version, state
}

// digestDelivery delivers the KindImageDigest event of one exec event that
// went out with its digest pending: PID, At and ImageVersion are the exec
// event's, and the digest read, or failed. The digest event never goes out
// before the exec's own: a read that ends first is kept until sent is
// called, after the exec event is pushed.
type digestDelivery struct {
	push    func(Event)
	pid     int
	at      time.Time
	version string

	mu     sync.Mutex
	sent   bool
	early  bool
	digest Event
}

func newDigestDelivery(push func(Event), pid int, at time.Time) *digestDelivery {
	return &digestDelivery{push: push, pid: pid, at: at}
}

// follow is the hasher's callback once the read ends.
func (d *digestDelivery) follow(sum string, read bool) {
	event := Event{Kind: KindImageDigest, PID: d.pid, At: d.at, ImageVersion: d.version, ImageDigestState: DigestFailed}
	if read && sum != "" {
		event.ImageSHA256, event.ImageDigestState = sum, DigestRead
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.sent {
		d.early, d.digest = true, event
		return
	}
	d.push(event)
}

// execSent is called once the exec event is pushed.
func (d *digestDelivery) execSent() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = true
	if d.early {
		d.early = false
		d.push(d.digest)
	}
}

// clientImagePrewarmInterval is how often installed client images under the
// watched homes are looked up, so their digests are cached before the
// first exec of a new install (and the fork of its first tool call) needs
// them. A cached image costs one open and fstat.
const clientImagePrewarmInterval = 10 * time.Second

// maxPrewarmEntries bounds the versions-directory entries read per home and
// per cycle; the native installer keeps a few.
const maxPrewarmEntries = 32

// prewarmClientImages queues a hash of each installed native Claude image
// under homes that the cache has not seen, and returns how many images it
// opened. The digest is bound to the file's identity, not its path, so an
// exec of the same file later finds it. Every component below the home is
// the account's, so the versions directory is opened one component at a time
// without following links, at most maxPrewarmEntries entries are read, and
// each image is opened through the directory without following a link and
// only if it is a regular file within the size cap.
func prewarmClientImages(homes []string) int {
	if clientImages.off.Load() {
		return 0
	}
	opened := 0
	for _, home := range expandHomes(homes) {
		dir, err := openBelowHome(home, ".local", "share", "claude", "versions")
		if err != nil {
			continue
		}
		entries, _ := dir.ReadDir(maxPrewarmEntries)
		for _, entry := range entries {
			name := entry.Name()
			if !IsClaudeReleaseVersion(name) {
				continue
			}
			var stat unix.Stat_t
			if unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > maxClientImageBytes {
				continue
			}
			fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			opened++
			file := os.NewFile(uintptr(fd), filepath.Join(home, ".local/share/claude/versions", name))
			key, ok := statImageKey(file)
			if !ok {
				file.Close()
				continue
			}
			clientImages.digestOf(file, key, "uid:"+strconv.Itoa(int(stat.Uid)), nil)
		}
		dir.Close()
	}
	return opened
}

// openBelowHome opens the directory home/components..., following no link
// below home (the home itself is the configured path).
func openBelowHome(home string, components ...string) (*os.File, error) {
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range components {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), filepath.Join(append([]string{home}, components...)...)), nil
}

// localImageFS reports a file on a local file system. Images on network and
// FUSE file systems, whose contents and attributes the account or a remote
// controls and whose reads may never return, are not hashed.
func localImageFS(file *os.File) bool {
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil {
		return false
	}
	switch uint32(stat.Type) {
	case 0x65735546, // FUSE
		0x6969,     // NFS
		0x517b,     // SMB
		0xff534d42, // CIFS
		0xfe534d42, // SMB2
		0x00c36400, // Ceph
		0x01021997, // 9P
		0x5346414f, // AFS
		0x0bd00bd0: // Lustre
		return false
	}
	return true
}

// prewarm runs prewarmClientImages until ctx ends.
func (s *linuxSource) prewarm(ctx context.Context) {
	ticker := time.NewTicker(clientImagePrewarmInterval)
	defer ticker.Stop()
	for {
		prewarmClientImages(s.homeDirs)
		select {
		case <-ctx.Done():
			return
		case <-s.stopped:
			return
		case <-ticker.C:
		}
	}
}
