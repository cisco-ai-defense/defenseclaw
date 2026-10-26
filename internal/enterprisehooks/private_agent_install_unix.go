// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var privateUnixNPMPackages = map[string]string{
	"claudecode": "@anthropic-ai/claude-code",
	"copilot":    "@github/copilot",
	"codex":      "@openai/codex",
}

// privateUnixCaskTokens are the Homebrew casks that install each
// connector's native CLI under <prefix>/Caskroom/<token>/<version>/.
var privateUnixCaskTokens = map[string][]string{
	"claudecode": {"claude-code", "claude-code@latest"},
	"codex":      {"codex"},
	"copilot":    {"copilot-cli"},
}

// privateInstallMachinePrefixes are the machine-wide prefixes the scan
// reads: the same ones the version probe selects from, so a supported
// machine copy can never hide an older one in another machine prefix.
// Tests replace it so the build host's own installs stay out of results.
var privateInstallMachinePrefixes = func() []string { return machinePrefixes() }

func privateInstallContractReason(connector, version string) string {
	return unixNewRowVersionRefused(connector, version)
}

// UnixPrivateInstallConnectors names the connectors of names that
// DiscoverUnixPrivateAgentInstalls inspects.
func UnixPrivateInstallConnectors(names []string) []string {
	return privateInstallConnectors(names, func(name string) bool { return privateUnixNPMPackages[name] != "" })
}

// DiscoverUnixPrivateAgentInstalls runs in the enrolled user's discovery
// worker, with the user's credentials. It reads metadata only; no user
// executable runs. It inspects every npm-style prefix the version probe
// knows (per-user, version managers without truncation, Volta package
// images, the vendor's local install and the machine prefixes), every npm
// prefix at any depth below the home (npm install --prefix
// "$HOME/a/b/private", a project's dependencies, GAP-0988), the native
// installer's versions and the Homebrew casks. Every unsupported or unversioned copy is listed with its path; a
// part of the scan that could not finish is listed as incomplete with the
// reason.
func DiscoverUnixPrivateAgentInstalls(ctx context.Context, home string, connectors []string) []PrivateAgentInstall {
	if ctx == nil {
		ctx = context.Background()
	}
	wanted := UnixPrivateInstallConnectors(connectors)
	if len(wanted) == 0 {
		return nil
	}
	home = filepath.Clean(home)
	scan := newPrivateInstallScan()
	roots := []string{home}
	if connectorListed(wanted, "claudecode") {
		// Keep the vendor's known root even if the bounded deep walk cannot
		// finish listing the rest of the home.
		roots = append(roots, filepath.Join(home, ".claude", "local"))
	}
	prefixes, truncated := userNodePrefixesBounded(home, privateAgentInstallMaxVersionDirs)
	if truncated {
		scan.skipAll(wanted, PrivateInstallSkippedVersionManagers)
	}
	roots = append(roots, prefixes...)
	nested, complete := walkPrivateNPMPrefixes(ctx, home, privateInstallWalk{open: unixPrivateWalkOpener(home), unreachable: unixPrivateWalkUnreachable, homeLinks: true})
	if !complete {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
	}
	roots = append(roots, nested...)
	if ctx.Err() != nil {
		return scan.result()
	}
	machine := privateInstallMachinePrefixes()
	roots = append(roots, machine...)
	for _, connector := range wanted {
		if ctx.Err() != nil {
			scan.skipAll(wanted, PrivateInstallSkippedHome)
			return scan.result()
		}
		pkg := privateUnixNPMPackages[connector]
		// Volta stores each package in its own image, rather than directly
		// under tools/image. A supported selected image can hide an old one.
		connectorRoots := append(append([]string{}, roots...), filepath.Join(home, ".volta", "tools", "image", "packages", filepath.FromSlash(pkg)))
		for _, root := range connectorRoots {
			if ctx.Err() != nil {
				scan.skipAll(wanted, PrivateInstallSkippedHome)
				return scan.result()
			}
			for _, manifest := range nodeModulesPackage(root, pkg) {
				scanUnixNPMPackage(scan, home, connector, pkg, filepath.Dir(manifest))
			}
		}
	}
	if ctx.Err() != nil {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
		return scan.result()
	}
	if connectorListed(wanted, "claudecode") {
		local := filepath.Join(home, ".claude", "local")
		wrapper := filepath.Join(local, "claude")
		runnable, known := unixNPMPackageRunnable("claudecode", filepath.Join(local, "node_modules", "@anthropic-ai", "claude-code"))
		if !known {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
		} else if !runnable && unixAgentExecutablePresent(wrapper) {
			if identity, ok := unixCopyIdentity(wrapper); ok && scan.judge(identity) {
				scan.add(PrivateAgentInstall{Connector: "claudecode", Path: wrapper})
			}
		}
		scanUnixVersionDir(scan, home, "claudecode", filepath.Join(home, ".local", "share", "claude", "versions"), false)
	}
	for _, connector := range wanted {
		for _, prefix := range machine {
			if ctx.Err() != nil {
				scan.skipAll(wanted, PrivateInstallSkippedHome)
				return scan.result()
			}
			for _, token := range privateUnixCaskTokens[connector] {
				scanUnixVersionDir(scan, home, connector, filepath.Join(prefix, "Caskroom", token), true)
			}
		}
	}
	if ctx.Err() != nil {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
	}
	return scan.result()
}

// unixCopyIdentity is the real path a copy resolves to: links and
// equivalent spellings of one copy name the same identity.
func unixCopyIdentity(path string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	return filepath.Clean(resolved), true
}

// unixNPMPackageRunnable reports whether an agent's npm package holds an
// entry point (privateNPMEntries): a package record without one is a
// leftover, not a copy. known is false when the package.json or an entry
// point could not be read for another reason than being absent or out of
// the account's reach, so whether the copy runs is unknown.
func unixNPMPackageRunnable(connector, dir string) (runnable, known bool) {
	known = true
	manifest, err := readBoundedUnixFile(filepath.Join(dir, "package.json"))
	if err != nil && !unixEntryAbsent(err) {
		known = false
	}
	for _, entry := range privateNPMEntries(connector, manifest) {
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(entry)))
		switch {
		case err == nil && info.Mode().IsRegular():
			return true, true
		case err != nil && !unixEntryAbsent(err):
			known = false
		}
	}
	return false, known
}

// unixEntryAbsent reports a lookup error that means the account cannot run
// the file: it does not exist, a parent is not a directory, a link loops,
// or the account may not reach it. The scan runs with the account's own
// credentials.
func unixEntryAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ELOOP) || errors.Is(err, fs.ErrPermission)
}

// unixPrivateWalkUnreachable reports a listing error of the home walk that
// hides nothing the account can run: the folder is gone or is no folder, is
// a tool-owned tree the walk prunes (unixPrivateWalkPruned), or
// macOS privacy protection (EPERM) keeps the account's own tools out too,
// a documented limit. A searchable folder the account cannot list still
// lets it start a copy whose path it knows, regardless of the owner. An
// unsearchable folder the account owns can be made searchable by that account.
// Both leave the scan incomplete.
func unixPrivateWalkUnreachable(dir string, err error) bool {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, errPrivateWalkPruned) {
		return true
	}
	if !errors.Is(err, syscall.EACCES) {
		return false
	}
	// Looking up "." requires search permission on dir but not permission
	// to list its entries. Preserve the final component: filepath.Join
	// would clean it away and only check the searchable parent.
	_, statErr := os.Stat(dir + string(os.PathSeparator) + ".")
	if !errors.Is(statErr, fs.ErrPermission) {
		return false
	}
	info, statErr := os.Stat(dir)
	if statErr != nil {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(owner.Uid) != os.Geteuid()
}

// readBoundedUnixFile reads a regular file of at most
// unixAgentVersionMaxBytes. It never blocks on a FIFO planted in its place.
func readBoundedUnixFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > unixAgentVersionMaxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, unixAgentVersionMaxBytes)
	}
	return data, nil
}

func scanUnixNPMPackage(scan *privateInstallScan, home, connector, pkg, dir string) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return // absent (or a protected folder the user's own tools cannot list either)
	}
	identity, ok := unixCopyIdentity(dir)
	if !ok || !scan.judge(identity) {
		return
	}
	runnable, known := unixNPMPackageRunnable(connector, dir)
	if !known {
		scan.skip(connector, PrivateInstallSkippedLocation)
		return
	}
	if !runnable {
		return // a leftover package record without an entry point
	}
	manifest := filepath.Join(dir, "package.json")
	if !unixDiscoveryCandidateTrusted(home, dir) || !unixDiscoveryCandidateTrusted(home, manifest) {
		scan.add(PrivateAgentInstall{Connector: connector, Path: dir, Untrusted: true})
		return
	}
	version, ok := readUnixPackageVersion(manifest, pkg, false)
	if ok && privateInstallReason(connector, version) == "" {
		return
	}
	scan.add(PrivateAgentInstall{Connector: connector, Version: version, Path: dir})
}

// scanUnixVersionDir judges each release in a version-named directory: the
// native installer's executables (versions/<v>) or, with casks, Homebrew's
// Caskroom/<token>/<v>/ folders that hold the CLI.
func scanUnixVersionDir(scan *privateInstallScan, home, connector, dir string, casks bool) {
	f, err := os.Open(dir)
	if err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR) {
			scan.skip(connector, PrivateInstallSkippedLocation)
		}
		return
	}
	names, listErr := f.Readdirnames(privateAgentInstallMaxVersionDirs + 1)
	_ = f.Close()
	if listErr != nil && listErr != io.EOF {
		scan.skip(connector, PrivateInstallSkippedLocation)
		return
	}
	if len(names) > privateAgentInstallMaxVersionDirs {
		scan.skip(connector, PrivateInstallSkippedNativeVersions)
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		version := name
		if !validUnixAgentVersion(version) {
			if casks {
				continue // .metadata and other bookkeeping
			}
			version = ""
		}
		if casks {
			if !unixCaskReleaseRunnable(path) {
				continue
			}
		} else if !unixAgentExecutablePresent(path) {
			continue
		}
		identity, ok := unixCopyIdentity(path)
		if !ok || !scan.judge(identity) {
			continue
		}
		if !unixDiscoveryCandidateTrusted(home, path) {
			scan.add(PrivateAgentInstall{Connector: connector, Path: path, Untrusted: true})
			continue
		}
		if privateInstallReason(connector, version) == "" {
			continue
		}
		scan.add(PrivateAgentInstall{Connector: connector, Version: version, Path: path})
	}
}

// unixCaskReleaseRunnable reports whether a cask release folder holds an
// executable file at its top level (claude, codex-<arch>, copilot) or up
// to two folders below it (bin/codex, GAP-0989). A folder with more
// entries than the bound counts as runnable, so the release is judged by
// its version instead of being skipped.
func unixCaskReleaseRunnable(dir string) bool {
	return unixExecutableWithin(dir, 2)
}

func unixExecutableWithin(dir string, depth int) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	entries, _ := f.ReadDir(privateAgentInstallMaxVersionDirs + 1)
	_ = f.Close()
	if len(entries) > privateAgentInstallMaxVersionDirs {
		return true
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.Type() == fs.ModeDir {
			if depth > 0 && unixExecutableWithin(path, depth-1) {
				return true
			}
			continue
		}
		if unixAgentExecutablePresent(path) {
			return true
		}
	}
	return false
}

// UnixPrivateInstallPathAllowed reports whether a copy the per-user worker
// names lies where the scan looks: inside the account's home, in a machine
// prefix or in the shared Linuxbrew prefix. The root parent turns any other
// path into an incomplete scan instead of recording it.
func UnixPrivateInstallPathAllowed(home, path string) bool {
	roots := append([]string{filepath.Clean(home), "/home/linuxbrew/.linuxbrew"}, privateInstallMachinePrefixes()...)
	for _, root := range roots {
		if pathInside(root, path) {
			return true
		}
	}
	return false
}
