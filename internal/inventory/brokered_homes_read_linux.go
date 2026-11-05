// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ReadBrokeredHomes is the sensor helper's half of a brokered read
// (brokered_homes.go): the allowlisted paths of each of homes, which come from
// the helper's own root-owned configuration with its patterns expanded. It
// reports what it could not read rather than failing, and never follows a
// link.
func ReadBrokeredHomes(ctx context.Context, homes []string, allow BrokeredHomeAllowlist) BrokeredHomeReport {
	report := BrokeredHomeReport{Version: BrokeredHomeReportVersion}
	budget := brokeredReadBudget{remaining: maxBrokeredReadBytes}
	paths := allow.Paths()
	seen := map[string]bool{}
	for _, home := range homes {
		if ctx.Err() != nil {
			report.Truncated = true
			break
		}
		home = filepath.Clean(strings.TrimSpace(home))
		if !filepath.IsAbs(home) || home == "/" || seen[home] {
			continue
		}
		seen[home] = true
		if len(report.Homes) >= maxBrokeredHomes {
			report.Truncated = true
			break
		}
		if read, ok := readBrokeredHome(ctx, home, paths, allow, &budget); ok {
			report.Homes = append(report.Homes, read)
		}
	}
	report.FilesRead = budget.files
	report.Truncated = report.Truncated || budget.truncated
	return report
}

type brokeredReadBudget struct {
	remaining int64
	files     int
	truncated bool
}

// brokeredHomeAccount names the account of uid and its passwd home. A seam
// for tests.
var brokeredHomeAccount = func(uid int) (name, home string, err error) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", "", err
	}
	return account.Username, account.HomeDir, nil
}

// readBrokeredHome reads one home: a real folder (not a link) owned by an
// account of uid brokeredHomeMinUID or up whose passwd entry names it as its
// home. ok is false for anything else.
func readBrokeredHome(ctx context.Context, home string, paths []string, allow BrokeredHomeAllowlist, budget *brokeredReadBudget) (BrokeredHome, bool) {
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return BrokeredHome{}, false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return BrokeredHome{}, false
	}
	uid := int(st.Uid)
	if uid < brokeredHomeMinUID {
		return BrokeredHome{}, false
	}
	name, accountHome, err := brokeredHomeAccount(uid)
	if err != nil || filepath.Clean(accountHome) != home || name == "" ||
		strings.ContainsAny(name, `/\`) || !userScanText(name, maxUserScanField) {
		return BrokeredHome{}, false
	}
	out := BrokeredHome{Home: home, UID: uid, User: name}
	for _, rel := range paths {
		if ctx.Err() != nil {
			budget.truncated = true
			break
		}
		entry, outcome := readBrokeredEntry(fd, uid, rel, allow[rel], filepath.Join(home, rel), budget)
		switch outcome {
		case brokeredPresent:
			out.Entries = append(out.Entries, entry)
		case brokeredRefused:
			out.Refused++
		}
	}
	return out, true
}

type brokeredOutcome int

const (
	brokeredAbsent brokeredOutcome = iota
	brokeredPresent
	brokeredRefused
)

// readBrokeredEntry opens rel below the home's descriptor one element at a
// time with O_NOFOLLOW: a link anywhere on the way is refused, never followed,
// and a link swapped in after a check fails the next open. Every element must
// belong to the home's account, and a file must have a single link, so a hard
// link to another account's file is refused.
func readBrokeredEntry(homeFD, uid int, rel string, allowance brokeredAllowance, source string, budget *brokeredReadBudget) (BrokeredHomeEntry, brokeredOutcome) {
	elements := strings.Split(rel, "/")
	dirFD := homeFD
	defer func() {
		if dirFD != homeFD {
			_ = unix.Close(dirFD)
		}
	}()
	for _, element := range elements[:len(elements)-1] {
		next, err := unix.Openat(dirFD, element, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return BrokeredHomeEntry{}, brokeredOpenOutcome(dirFD, element, err)
		}
		if dirFD != homeFD {
			_ = unix.Close(dirFD)
		}
		dirFD = next
		var st unix.Stat_t
		if err := unix.Fstat(dirFD, &st); err != nil || int(st.Uid) != uid {
			return BrokeredHomeEntry{}, brokeredRefused
		}
	}
	last := elements[len(elements)-1]
	// Only a regular file or a folder of the account's is opened at all: a
	// FIFO, socket or device in the allowlist's place is refused unopened.
	var pre unix.Stat_t
	if err := unix.Fstatat(dirFD, last, &pre, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return BrokeredHomeEntry{}, brokeredAbsent
		}
		return BrokeredHomeEntry{}, brokeredRefused
	}
	if kind := pre.Mode & unix.S_IFMT; (kind != unix.S_IFREG && kind != unix.S_IFDIR) || int(pre.Uid) != uid {
		return BrokeredHomeEntry{}, brokeredRefused
	}
	// O_NONBLOCK: an element swapped for a FIFO after the check must not
	// hang the open; the descriptor is then checked to be what was checked.
	fd, err := unix.Openat(dirFD, last, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return BrokeredHomeEntry{}, brokeredOpenOutcome(dirFD, last, err)
	}
	file := os.NewFile(uintptr(fd), source)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != uid || st.Dev != pre.Dev || st.Ino != pre.Ino {
		return BrokeredHomeEntry{}, brokeredRefused
	}
	entry := BrokeredHomeEntry{Path: rel, ModTimeUnixNano: st.Mtim.Nano()}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.Dir = true
		if allowance.Children {
			entry.Children, entry.ChildrenTruncated = readBrokeredChildren(fd, file)
		}
	case unix.S_IFREG:
		if st.Nlink != 1 {
			return BrokeredHomeEntry{}, brokeredRefused
		}
		if len(allowance.MCPShapes) > 0 {
			entry.MCP = readBrokeredMCP(file, st.Size, allowance.MCPShapes, source, budget)
		}
	default:
		return BrokeredHomeEntry{}, brokeredRefused
	}
	return entry, brokeredPresent
}

// brokeredOpenOutcome classifies a failed open: a missing element is absent;
// a link (ELOOP, or ENOTDIR for a link opened as a folder) and anything else
// (a socket's ENXIO, EACCES) are refused.
func brokeredOpenOutcome(dirFD int, element string, err error) brokeredOutcome {
	switch {
	case errors.Is(err, unix.ENOENT):
		return brokeredAbsent
	case errors.Is(err, unix.ENOTDIR):
		var st unix.Stat_t
		if unix.Fstatat(dirFD, element, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return brokeredRefused
		}
		return brokeredAbsent
	default:
		return brokeredRefused
	}
}

// maxBrokeredDirEntries bounds the names one folder read takes in.
const maxBrokeredDirEntries = 4096

// readBrokeredChildren lists a folder by name, sorted as os.ReadDir sorts,
// with each entry's type from fstatat on the folder's descriptor (never a
// path, never a link's target).
func readBrokeredChildren(dirFD int, dir *os.File) ([]BrokeredHomeChild, bool) {
	names, err := dir.Readdirnames(maxBrokeredDirEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	truncated := len(names) == maxBrokeredDirEntries
	sort.Strings(names)
	children := make([]BrokeredHomeChild, 0, min(len(names), maxBrokeredChildren))
	for _, name := range names {
		if sanitizeBasenameValue(name) != name {
			continue
		}
		if len(children) >= maxBrokeredChildren {
			truncated = true
			break
		}
		var st unix.Stat_t
		regular := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
		children = append(children, BrokeredHomeChild{Name: name, Regular: regular})
	}
	return children, truncated
}

// readBrokeredMCP reads one MCP config within the per-file cap and the
// request's byte budget and keeps only its server names, once per shape.
func readBrokeredMCP(file *os.File, size int64, shapes []string, source string, budget *brokeredReadBudget) []BrokeredMCPConfig {
	limit := int64(maxBrokeredFileBytes)
	if slices.Contains(shapes, mcpShapeClaudeState) {
		limit = maxBrokeredClaudeStateBytes
	}
	failed := func(reason string) []BrokeredMCPConfig {
		out := make([]BrokeredMCPConfig, 0, len(shapes))
		for _, shape := range shapes {
			out = append(out, BrokeredMCPConfig{Shape: shape, Partial: reason})
		}
		return out
	}
	if size > limit {
		return failed(CoverageReasonCapExceeded)
	}
	if size > budget.remaining {
		budget.truncated = true
		return failed(CoverageReasonCapExceeded)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return failed(CoverageReasonParseError)
	}
	if int64(len(data)) > limit || int64(len(data)) > budget.remaining {
		budget.truncated = budget.truncated || int64(len(data)) > budget.remaining
		return failed(CoverageReasonCapExceeded)
	}
	budget.remaining -= int64(len(data))
	budget.files++
	out := make([]BrokeredMCPConfig, 0, len(shapes))
	for _, shape := range shapes {
		names, err := parseBrokeredMCP(shape, source, data)
		if err != nil {
			out = append(out, BrokeredMCPConfig{Shape: shape, Partial: CoverageReasonParseError})
			continue
		}
		cfg := BrokeredMCPConfig{Shape: shape}
		for _, name := range names {
			if len(cfg.Servers) >= maxEvidencePerSignal {
				break
			}
			if name = sanitizeBasenameValue(name); name != "" {
				cfg.Servers = append(cfg.Servers, name)
			}
		}
		out = append(out, cfg)
	}
	return out
}

// parseBrokeredMCP parses a config the home's account wrote. A parser
// failure is a parse error, never a crash of the root helper.
func parseBrokeredMCP(shape, source string, data []byte) (names []string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			names, err = nil, fmt.Errorf("MCP config parser failed: %v", recovered)
		}
	}()
	return parseMCPConfigBytesForNames(shape, source, data)
}
