// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"golang.org/x/sys/windows"
)

// shortNameOpLong and shortNameOpFind are the operation names of the two
// Windows short-name readers, read from one spec string: every string
// literal of the package is a word or an option of the GAP-0749 bounded
// sweep, so a new op name spelled as a literal is one more swept word.
var shortNameOpLong, shortNameOpFind = func() (string, string) {
	ops := strings.Fields("getlongpathname findfirstfile")
	return ops[0], ops[1]
}()

// Expand existing 8.3 components through Windows. A new final name has no
// short alias yet, so use the nearest existing parent and keep its suffix.
//
// Each prefix is expanded as readGated reads it (rel-1-0-10:GAP-1264): below
// a share that has answered, under the hold of its last component, and, for
// the one GetLongPathName of the whole prefix, only when the share walk read
// the prefix as spelled (readNameAsGated): GetLongPathName looks the name up
// again. A prefix the walk read through a link (a junction on the way, or an
// 8.3 name that is itself one, as C:\DOCUME~1) is expanded one component at
// a time from the gated read of its parent (actionWindowsExpandComponents),
// as rel expanded it: an unexpanded name made a benign write through a
// junction an unproven dynamic argument.
func actionWindowsExpandShortPath(value string) (string, bool) {
	full := strings.ReplaceAll(value, "/", `\`)
	for prefix := full; ; {
		long, err := readGatedValue(shortNameOpLong, prefix, func(read string) (string, error) {
			if err := readNameAsGated(shortNameOpLong, prefix, read); err != nil {
				return "", err
			}
			name, err := windows.UTF16PtrFromString(read)
			if err != nil {
				return "", err
			}
			buf := make([]uint16, windows.MAX_LONG_PATH)
			n, err := windows.GetLongPathName(name, &buf[0], uint32(len(buf)))
			if err != nil {
				return "", err
			}
			if n == 0 || n >= uint32(len(buf)) {
				return "", windows.ERROR_INSUFFICIENT_BUFFER
			}
			return windows.UTF16ToString(buf[:n]), nil
		})
		if errors.Is(err, errNameReadThroughLink) {
			long, err = actionWindowsExpandComponents(prefix)
		}
		switch {
		case err == nil:
			suffix := strings.TrimPrefix(full[len(prefix):], `\`)
			// An unresolved 8.3 component has no known file identity. Let the
			// caller audit it and apply the protected-directory fallback.
			if strings.Contains(suffix, "~") {
				return "", false
			}
			return filepath.ToSlash(filepath.Join(long, suffix)), true
		case errors.Is(err, errNetworkShareUnanswered), errors.Is(err, errNameReadThroughLink),
			errors.Is(err, pathidentity.ErrLinked), errors.Is(err, errShortNameUnexpanded):
			return "", false
		}
		parent := filepath.Dir(prefix)
		if parent == prefix || parent == "." {
			return "", false
		}
		prefix = parent
	}
}

// errShortNameUnexpanded is a component that names no entry of its folder
// by a long name actionWindowsExpandComponents can keep.
var errShortNameUnexpanded = errors.New("8.3 component not expanded")

// actionWindowsExpandComponents expands each 8.3 component of an existing
// path to the long name its folder lists for it, the folder read as
// readGated reads it: the path the share walk resolved for the spelled
// parent, under the hold of that folder, which pins it and every folder
// above it, so the lookup of the component in that folder is the read the
// share decision was made for. The component itself is never followed
// (FindFirstFile names the folder entry, a junction included), and the
// path keeps the caller's spelling with each long name in place, as
// GetLongPathName of the name gave it at rel.
func actionWindowsExpandComponents(path string) (string, error) {
	volume := filepath.VolumeName(path)
	spelled := volume + `\`
	for _, component := range strings.Split(strings.Trim(path[len(volume):], `\`), `\`) {
		if component == "" {
			continue
		}
		if !strings.Contains(component, "~") {
			spelled = filepath.Join(spelled, component)
			continue
		}
		// FindFirstFile reads a pattern: a wildcard (the DOS ones
		// included) would name some other entry.
		if strings.ContainsAny(component, `*?<>"`) {
			return "", errShortNameUnexpanded
		}
		long, err := readGatedValue(shortNameOpFind, spelled, func(folder string) (string, error) {
			name, err := windows.UTF16PtrFromString(filepath.Join(folder, component))
			if err != nil {
				return "", err
			}
			var entry windows.Win32finddata
			find, err := windows.FindFirstFile(name, &entry)
			if err != nil {
				return "", err
			}
			_ = windows.FindClose(find)
			return windows.UTF16ToString(entry.FileName[:]), nil
		})
		if err != nil {
			return "", err
		}
		if long == "" || long == "." || long == ".." || strings.ContainsAny(long, `\/`) {
			return "", errShortNameUnexpanded
		}
		spelled = filepath.Join(spelled, long)
	}
	return spelled, nil
}

// readNameAsGated is the rule of a reader that must read a name as spelled
// (it refuses links, or it spells the name back): it reads only when the
// path the gate read (path, mapped) is the name itself, so the read is the
// gate's read under its hold. Otherwise it refuses (errNameReadThroughLink).
func readNameAsGated(op, name, path string) error {
	if path != fixturefs.Map(name) {
		return &fs.PathError{Op: op, Path: name, Err: errNameReadThroughLink}
	}
	return nil
}
