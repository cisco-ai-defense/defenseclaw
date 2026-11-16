//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

	"golang.org/x/sys/unix"
)

// IntegrityManifestRelPath is the code integrity manifest the installer
// writes under the install root, in `shasum -a 256` format: one
// `<64 hex>  <path>` line per file (a `*` before the path is accepted), with
// paths relative to the install root or absolute under it.
const IntegrityManifestRelPath = "etc/integrity.sha256"

const (
	integrityManifestMaxBytes = 1 << 20
	integrityFileMaxBytes     = 1 << 30
)

// IntegrityFinding is one code integrity finding.
type IntegrityFinding struct {
	Path     string
	Reason   string
	Expected string
	Actual   string
	Detail   string
}

// integrityCovered reports whether rel (slash form, relative to the install
// root) is a file the manifest covers: bin/*, lib/*.sh and libexec/*, one
// level deep.
func integrityCovered(rel string) bool {
	dir, name := filepath.Split(rel)
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	switch strings.TrimSuffix(dir, "/") {
	case "bin", "libexec":
		return true
	case "lib":
		return strings.HasSuffix(name, ".sh")
	default:
		return false
	}
}

// ParseIntegrityManifest reads a `shasum -a 256` manifest. Paths are returned
// relative to root in slash form; entries outside root, outside the covered
// folders, or malformed are reported in skipped.
func ParseIntegrityManifest(root string, data []byte) (entries map[string]string, skipped []string) {
	root = filepath.Clean(root)
	entries = map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		digest, rest, ok := strings.Cut(line, " ")
		if !ok || len(digest) != sha256.Size*2 {
			skipped = append(skipped, line)
			continue
		}
		if _, err := hex.DecodeString(digest); err != nil {
			skipped = append(skipped, line)
			continue
		}
		path := strings.TrimLeft(rest, " ")
		path = strings.TrimPrefix(path, "*")
		if filepath.IsAbs(path) {
			rel, err := filepath.Rel(root, filepath.Clean(path))
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				skipped = append(skipped, line)
				continue
			}
			path = rel
		}
		path = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(path, "./")))
		if !integrityCovered(path) {
			skipped = append(skipped, line)
			continue
		}
		entries[path] = strings.ToLower(digest)
	}
	return entries, skipped
}

type integrityStamp struct {
	dev   int64
	ino   uint64
	size  int64
	mtime unix.Timespec
	ctime unix.Timespec
}

// IntegrityChecker compares the installed code against the installer's
// manifest on each guardian tick. Findings are advisory: a mismatch is logged
// as defenseclaw_boundary and the component keeps running; owner and mode are
// repaired by the install tree repair, never here, and content only by a
// reinstall. A file's hash is recomputed only when its identity or times
// change, so an unchanged tree costs one lstat per file.
type IntegrityChecker struct {
	root string

	mu              sync.Mutex
	hashes          map[string]integrityCachedHash
	active          map[string]struct{}
	manifestDegrade string
}

type integrityCachedHash struct {
	stamp  integrityStamp
	digest string
}

// NewIntegrityChecker returns a checker for the install root.
func NewIntegrityChecker(root string) *IntegrityChecker {
	if strings.TrimSpace(root) == "" {
		root = DarwinManagedInstallRoot
	}
	return &IntegrityChecker{root: filepath.Clean(root), hashes: map[string]integrityCachedHash{}}
}

// Check compares the tree with the manifest, logs new findings once per streak
// and returns every current finding. It never fails.
func (c *IntegrityChecker) Check() []IntegrityFinding {
	c.mu.Lock()
	defer c.mu.Unlock()
	manifestPath := filepath.Join(c.root, IntegrityManifestRelPath)
	data, err := readIntegrityFile(manifestPath, integrityManifestMaxBytes)
	if err != nil {
		reason := "integrity_manifest_missing"
		if !errors.Is(err, fs.ErrNotExist) {
			reason = "integrity_manifest_unreadable"
		}
		if c.manifestDegrade != reason {
			c.manifestDegrade = reason
			EmitResilienceEvent(MarkerDegraded, map[string]string{
				"subsystem": "code_integrity",
				"path":      manifestPath,
				"reason":    reason,
			})
		}
		c.active = nil
		return nil
	}
	c.manifestDegrade = ""
	entries, _ := ParseIntegrityManifest(c.root, data)

	var findings []IntegrityFinding
	listed := map[string]struct{}{}
	rels := make([]string, 0, len(entries))
	for rel := range entries {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		listed[rel] = struct{}{}
		findings = append(findings, c.checkFile(rel, entries[rel])...)
	}
	for _, dir := range []string{"bin", "lib", "libexec"} {
		children, err := os.ReadDir(filepath.Join(c.root, dir))
		if err != nil {
			continue
		}
		for _, child := range children {
			rel := dir + "/" + child.Name()
			if _, ok := listed[rel]; ok || !integrityCovered(rel) || child.IsDir() {
				continue
			}
			findings = append(findings, IntegrityFinding{Path: filepath.Join(c.root, rel), Reason: "code_unlisted"})
		}
	}

	current := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.Path + "\x00" + finding.Reason + "\x00" + finding.Actual + "\x00" + finding.Detail
		current[key] = struct{}{}
		if _, seen := c.active[key]; seen {
			continue
		}
		fields := map[string]string{"path": finding.Path, "reason": finding.Reason}
		if finding.Expected != "" {
			fields["expected_sha256"] = finding.Expected
		}
		if finding.Actual != "" {
			fields["actual_sha256"] = finding.Actual
		}
		if finding.Detail != "" {
			fields["principal"] = finding.Detail
		}
		EmitResilienceEvent(MarkerBoundary, fields)
	}
	c.active = current
	return findings
}

func (c *IntegrityChecker) checkFile(rel, expected string) []IntegrityFinding {
	path := filepath.Join(c.root, filepath.FromSlash(rel))
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return []IntegrityFinding{{Path: path, Reason: "code_missing", Expected: expected}}
		}
		ReportPolicyDenial("stat", path, err)
		return []IntegrityFinding{{Path: path, Reason: "code_unreadable", Expected: expected}}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return []IntegrityFinding{{Path: path, Reason: "code_not_regular", Expected: expected}}
	}
	var findings []IntegrityFinding
	// Root executes or sources these files, so an owner other than root or a
	// group or other write bit lets someone else change what root runs.
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		findings = append(findings, IntegrityFinding{
			Path:   path,
			Reason: "code_untrusted_writer",
			Detail: fmt.Sprintf("uid:%d mode:%04o", st.Uid, st.Mode&0o7777),
		})
	}
	stamp := integrityStamp{dev: int64(st.Dev), ino: st.Ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
	digest := ""
	if cached, ok := c.hashes[rel]; ok && cached.stamp == stamp {
		digest = cached.digest
	} else {
		sum, err := hashIntegrityFile(path)
		if err != nil {
			ReportPolicyDenial("read", path, err)
			return append(findings, IntegrityFinding{Path: path, Reason: "code_unreadable", Expected: expected})
		}
		digest = sum
		c.hashes[rel] = integrityCachedHash{stamp: stamp, digest: digest}
	}
	if digest != expected {
		findings = append(findings, IntegrityFinding{Path: path, Reason: "code_hash_mismatch", Expected: expected, Actual: digest})
	}
	return findings
}

func openIntegrityFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func hashIntegrityFile(path string) (string, error) {
	file, err := openIntegrityFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, integrityFileMaxBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readIntegrityFile(path string, maxBytes int64) ([]byte, error) {
	file, err := openIntegrityFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %s bytes", path, strconv.FormatInt(maxBytes, 10))
	}
	return data, nil
}
