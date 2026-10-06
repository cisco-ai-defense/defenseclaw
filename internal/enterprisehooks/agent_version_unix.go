//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Unix agent-version discovery for the standalone enumerator.
//
// DiscoverUnixAgentVersion runs inside the per-user apply-target worker
// with the target user's credentials, so reading package metadata under
// the user's home and executing `<cli> --version` happen with that user's
// permissions — never root's. DiscoverUnixMachineAgentVersion runs as root
// but trusts only root-owned, non-writable machine-scoped metadata; it
// lets the enumerator defer a row for a user whose home does not exist
// yet when the agent is installed machine-wide.

const (
	unixAgentVersionMaxBytes = 64 << 10
	unixAgentVersionMaxRunes = 128
	unixAgentVersionTimeout  = 5 * time.Second
	unixAgentVersionOutput   = 512
)

// TrustedBinPrefixesEnv lists extra administrator-controlled install
// prefixes (colon-separated) whose bin/ and lib/node_modules/ the
// discovery searches, e.g. an MDM-managed /opt/agents.
const TrustedBinPrefixesEnv = "DEFENSECLAW_TRUSTED_BIN_PREFIXES"

var unixAgentSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?([.+-][0-9A-Za-z.+-]*)?$`)

// unixAgentProbe describes where a connector's CLI leaves metadata.
type unixAgentProbe struct {
	npmPackages []string // package names, checked for a matching "name"
	versionDirs []string // home-relative dirs whose children are version-named
	binaries    []string // CLI names for the `--version` fallback
	// stateEnv names the variable that relocates the agent state directory.
	// The probe points it at a private scratch directory: the enumerator
	// sees homes read-only, and some agents (Hermes) refuse to print their
	// version when they cannot take a lock in their state directory.
	stateEnv string
	// uvTool names a `uv tool install` environment (tool, distribution)
	// whose dist-info directory carries the version, for Python CLIs that
	// take too long to start for the --version probe.
	uvTool [2]string
	// stamp is a home-relative JSON install stamp that records the release
	// ("displayVersion", else "baseVersion"), for CLIs that no longer print a
	// version outside their own environment: a current Hermes refuses
	// --version when no dependency environment is committed for the install
	// the probe's scratch HERMES_HOME points at. Reading the stamp executes
	// nothing.
	stamp string
}

var unixAgentProbes = map[string]unixAgentProbe{
	"codex": {npmPackages: []string{"@openai/codex"}, binaries: []string{"codex"}},
	// Claude Desktop's embedded build is a desktop surface
	// (DiscoverUnixAgentSurfaces), not the CLI.
	"claudecode": {npmPackages: []string{"@anthropic-ai/claude-code"}, versionDirs: []string{".local/share/claude/versions"}, binaries: []string{"claude"}},
	"cursor":     {versionDirs: []string{".local/share/cursor-agent/versions"}, binaries: []string{"cursor-agent", "agent"}},
	"copilot":    {npmPackages: []string{"@github/copilot"}, binaries: []string{"copilot"}},
	"opencode":   {npmPackages: []string{"opencode-ai"}, binaries: []string{"opencode"}},
	"amp":        {npmPackages: []string{"@ampcode/cli"}, binaries: []string{"amp"}},
	"devin":      {binaries: []string{"devin"}},
	"hermes":     {binaries: []string{"hermes"}, stateEnv: "HERMES_HOME", stamp: ".hermes/hermes-agent/install-stamp.json"},
	"openhands":  {binaries: []string{"openhands"}, uvTool: [2]string{"openhands", "openhands"}},
	"omnigent":   {binaries: []string{"omnigent"}, uvTool: [2]string{"omnigent", "omnigent"}},
	// "antigravity" is the IDE launcher, a desktop surface that is never
	// run (DiscoverUnixAgentSurfaces).
	"antigravity": {binaries: []string{"agy"}},
	"kiro":        {binaries: []string{"kiro-cli"}},
}

// UnixAgentProbeKnown reports whether discovery knows connector.
func UnixAgentProbeKnown(connector string) bool {
	_, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	return ok
}

// userNodePrefixes lists the per-user npm-style install prefixes. In the
// standalone per-user worker it adds npm's common custom prefixes and the
// one ~/.npmrc names, yarn classic, pnpm, each installed Node of nvm, fnm,
// asdf and mise (newest first) and Linuxbrew. Those need reads inside the
// home, so they are searched only by a process running as the target user
// (the worker); other callers keep the original fixed list. A prefix
// outside the home (the shared /home/linuxbrew/.linuxbrew, an ~/.npmrc
// prefix elsewhere) belongs to whoever installed it, so discovery reads it
// only when unixDiscoveryCandidateTrusted admits it.
func userNodePrefixes(home string) []string {
	prefixes := []string{
		filepath.Join(home, ".npm-global"),
		filepath.Join(home, ".local"),
		filepath.Join(home, ".bun", "install", "global"),
		filepath.Join(home, ".volta", "tools", "image"),
	}
	if !unixUserDiscoveryExtended() {
		return prefixes
	}
	if prefix := userNPMRCPrefix(home); prefix != "" {
		prefixes = append(prefixes, prefix)
	}
	prefixes = append(prefixes,
		filepath.Join(home, ".npm-packages"),
		filepath.Join(home, ".config", "yarn", "global"),
	)
	for _, pattern := range userVersionedNodePrefixPatterns(home) {
		prefixes = append(prefixes, newestVersionedDirs(pattern, unixVersionedPrefixLimit)...)
	}
	return append(prefixes,
		filepath.Join(home, ".linuxbrew"),
		"/home/linuxbrew/.linuxbrew",
	)
}

// unixUserDiscoveryExtended reports whether discovery may look through the
// home for version-manager installs: only the standalone profile's per-user
// worker, which runs as the target user, never a root process.
var unixUserDiscoveryExtended = func() bool {
	return StandaloneUnix() && os.Geteuid() != 0
}

// unixVersionedPrefixLimit bounds the installed Node versions searched per
// version manager.
const unixVersionedPrefixLimit = 16

// userVersionedNodePrefixPatterns are globs whose matches are Node install
// prefixes (bin/ and lib/node_modules/ below them) or pnpm global
// directories (node_modules/ below them).
func userVersionedNodePrefixPatterns(home string) []string {
	return []string{
		filepath.Join(home, ".nvm", "versions", "node", "*"),
		filepath.Join(home, ".local", "share", "fnm", "node-versions", "*", "installation"),
		filepath.Join(home, "Library", "Application Support", "fnm", "node-versions", "*", "installation"),
		filepath.Join(home, ".fnm", "node-versions", "*", "installation"),
		filepath.Join(home, ".asdf", "installs", "nodejs", "*"),
		filepath.Join(home, ".local", "share", "mise", "installs", "node", "*"),
		filepath.Join(home, ".local", "share", "pnpm", "global", "*"),
		filepath.Join(home, "Library", "pnpm", "global", "*"),
	}
}

// newestVersionedDirs expands pattern to real directories, newest version
// first (the version is the first path element the wildcard matched,
// "v22.11.0" or "22.11.0"), at most limit of them.
func newestVersionedDirs(pattern string, limit int) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	star := strings.Index(pattern, "*")
	versionOf := func(match string) string {
		rest := match[star:]
		if i := strings.IndexRune(rest, filepath.Separator); i >= 0 {
			rest = rest[:i]
		}
		return strings.TrimPrefix(rest, "v")
	}
	var dirs []string
	for _, match := range matches {
		if info, err := os.Lstat(match); err == nil && info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	sort.SliceStable(dirs, func(i, j int) bool { return compareUnixVersions(versionOf(dirs[i]), versionOf(dirs[j])) > 0 })
	if len(dirs) > limit {
		dirs = dirs[:limit]
	}
	return dirs
}

// userNPMRCPrefix returns the npm global prefix set in ~/.npmrc
// ("prefix=~/.npm-packages", "prefix=${HOME}/tools"), or "".
func userNPMRCPrefix(home string) string {
	path := filepath.Join(home, ".npmrc")
	// A regular file only, opened without following a link or blocking on
	// a FIFO, so the file cannot stall discovery.
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil || len(data) > unixAgentVersionMaxBytes {
		return ""
	}
	prefix := ""
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(key) != "prefix" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch {
		case strings.HasPrefix(value, "~/"):
			value = filepath.Join(home, value[2:])
		case strings.HasPrefix(value, "${HOME}/"):
			value = filepath.Join(home, strings.TrimPrefix(value, "${HOME}/"))
		case strings.HasPrefix(value, "$HOME/"):
			value = filepath.Join(home, strings.TrimPrefix(value, "$HOME/"))
		}
		prefix = value // the last assignment wins, as in npm
	}
	if prefix == "" || !filepath.IsAbs(prefix) || strings.ContainsAny(prefix, "\x00:") || filepath.Clean(prefix) == "/" {
		return ""
	}
	return filepath.Clean(prefix)
}

// machinePrefixes lists machine-wide install prefixes; tests replace it so
// the developer's own installs do not leak into assertions.
var machinePrefixes = defaultMachinePrefixes

func defaultMachinePrefixes() []string {
	prefixes := []string{"/usr/local", "/usr", "/opt/homebrew"}
	for _, extra := range filepath.SplitList(os.Getenv(TrustedBinPrefixesEnv)) {
		extra = filepath.Clean(strings.TrimSpace(extra))
		if filepath.IsAbs(extra) && extra != "/" {
			prefixes = append(prefixes, extra)
		}
	}
	return prefixes
}

func nodeModulesPackage(prefix, pkg string) []string {
	// npm uses <prefix>/lib/node_modules; bun's global dir is itself
	// node_modules-rooted.
	return []string{
		filepath.Join(prefix, "lib", "node_modules", filepath.FromSlash(pkg), "package.json"),
		filepath.Join(prefix, "node_modules", filepath.FromSlash(pkg), "package.json"),
	}
}

// DiscoverUnixAgentVersion finds connector's installed version for home.
// allowExec enables the `--version` fallback; callers set it only when
// already running with the target user's credentials.
func DiscoverUnixAgentVersion(ctx context.Context, home, connector string, allowExec bool) (string, string) {
	connector = strings.ToLower(strings.TrimSpace(connector))
	probe, ok := unixAgentProbes[connector]
	if !ok {
		return "", fmt.Sprintf("no version probe for connector %s", connector)
	}
	home = filepath.Clean(home)
	userPrefixes := userNodePrefixes(home)
	for _, pkg := range probe.npmPackages {
		prefixes := userPrefixes
		if unixUserDiscoveryExtended() {
			// Volta keeps each global package in its own image.
			prefixes = append([]string{filepath.Join(home, ".volta", "tools", "image", "packages", filepath.FromSlash(pkg))}, userPrefixes...)
		}
		for _, prefix := range append(append([]string{}, prefixes...), machinePrefixes()...) {
			for _, candidate := range nodeModulesPackage(prefix, pkg) {
				if !unixDiscoveryCandidateTrusted(home, candidate) {
					continue
				}
				if version, ok := readUnixPackageVersion(candidate, pkg, false); ok {
					return version, ""
				}
			}
		}
	}
	for _, dir := range probe.versionDirs {
		if version := newestVersionDir(filepath.Join(home, filepath.FromSlash(dir))); version != "" {
			return version, ""
		}
	}
	if probe.uvTool[0] != "" {
		if version := readUVToolVersion(home, probe.uvTool[0], probe.uvTool[1]); version != "" {
			return version, ""
		}
	}
	if probe.stamp != "" {
		stamp := filepath.Join(home, filepath.FromSlash(probe.stamp))
		if unixDiscoveryCandidateTrusted(home, stamp) {
			if version := readUnixInstallStampVersion(stamp); version != "" {
				return version, ""
			}
		}
	}
	if !allowExec {
		return "", fmt.Sprintf("no %s package metadata under this home", connector)
	}
	installedAt, installedNote := "", ""
	for index, binary := range probe.binaries {
		for _, candidate := range unixAgentBinaryCandidates(home, binary) {
			// A CLI outside the home that another account can change is
			// never run as this user: whoever controls it would run code as
			// every enrolled user on every enumeration cycle.
			trusted := unixDiscoveryCandidateTrusted(home, candidate)
			if trusted {
				if version := execUnixAgentVersion(ctx, candidate, home, probe.stateEnv); version != "" {
					return version, ""
				}
			}
			// Only the connector's own CLI name counts as evidence of an
			// install; a generic alias ("agent") could be anything.
			if index == 0 && installedAt == "" && unixAgentExecutablePresent(candidate) {
				installedAt = candidate
				if !trusted {
					installedNote = unixUntrustedCandidateNote
				}
			}
		}
	}
	if installedAt != "" {
		return "", UnixAgentUnversionedReasonPrefix + installedAt + installedNote
	}
	return "", fmt.Sprintf("no %s installation found for this user", connector)
}

// UnixAgentUnversionedReasonPrefix starts the discovery reason for an agent
// whose CLI exists for the user but printed no usable version. The
// enumerator cannot select a hook contract for it, so it reports the agent
// as unprotected instead of skipping it silently.
const UnixAgentUnversionedReasonPrefix = "installed, but its version could not be read: "

// unixUntrustedCandidateNote follows the path of an installed CLI that
// discovery did not run because an account other than root and the user can
// change it (the parent keeps the first 256 bytes of a reason).
const unixUntrustedCandidateNote = " (not run: accounts other than root and this user can change it; use a root-owned agent_prefixes path)"

// UnixAgentInstalledWithoutVersion reports whether a discovery reason names
// an installed agent whose version could not be read.
func UnixAgentInstalledWithoutVersion(reason string) bool {
	return strings.HasPrefix(reason, UnixAgentUnversionedReasonPrefix)
}

// DiscoverUnixAgentVersionStatically is DiscoverUnixAgentVersion without
// the `--version` fallback: it reads package metadata and, when there is
// none, reports the connector's own CLI found in the user's install
// locations as installed without a readable version. Nothing is executed,
// so it is safe in a home other users can write, where a CLI could have
// been planted.
func DiscoverUnixAgentVersionStatically(ctx context.Context, home, connector string) (string, string) {
	version, reason := DiscoverUnixAgentVersion(ctx, home, connector, false)
	if version != "" {
		return version, ""
	}
	probe, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	if !ok || len(probe.binaries) == 0 {
		return "", reason
	}
	for _, candidate := range unixAgentBinaryCandidates(filepath.Clean(home), probe.binaries[0]) {
		if unixAgentExecutablePresent(candidate) {
			return "", UnixAgentUnversionedReasonPrefix + candidate
		}
	}
	return "", reason
}

func unixAgentExecutablePresent(candidate string) bool {
	info, err := os.Stat(candidate)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// unixAdminPrefixRoots hold administrator install prefixes
// (<root>/<name>/bin/<cli>) that discovery searches only when
// enrollment.agent_prefixes names them; tests replace it.
var unixAdminPrefixRoots = []string{"/opt"}

// UnixAgentOutsideDiscovery returns connector's CLI when it is installed in
// an administrator prefix under /opt that discovery does not search, and
// that prefix. The enumerator reports such an agent as unprotected and names
// the setting that adds the prefix, instead of saying nothing while users
// run it without DefenseClaw hooks. Nothing is executed. Safe as root.
func UnixAgentOutsideDiscovery(connector string) (binary, prefix string) {
	probe, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	if !ok || len(probe.binaries) == 0 {
		return "", ""
	}
	searched := map[string]bool{}
	for _, known := range machinePrefixes() {
		searched[filepath.Clean(known)] = true
	}
	for _, root := range unixAdminPrefixRoots {
		matches, _ := filepath.Glob(filepath.Join(root, "*", "bin", probe.binaries[0]))
		sort.Strings(matches)
		for _, match := range matches {
			candidatePrefix := filepath.Dir(filepath.Dir(match))
			if searched[candidatePrefix] || !unixAgentExecutablePresent(match) {
				continue
			}
			return match, candidatePrefix
		}
	}
	return "", ""
}

// DiscoverUnixMachineAgentVersion reads only root-owned, non-writable
// machine-scoped package metadata. Safe to call as root.
func DiscoverUnixMachineAgentVersion(connector string) string {
	probe, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	if !ok {
		return ""
	}
	for _, pkg := range probe.npmPackages {
		for _, prefix := range machinePrefixes() {
			for _, candidate := range nodeModulesPackage(prefix, pkg) {
				if version, ok := readUnixPackageVersion(candidate, pkg, true); ok {
					return version
				}
			}
		}
	}
	return ""
}

func unixAgentBinaryCandidates(home, binary string) []string {
	dirs := unixAgentDiscoveryDirs(home)
	candidates := make([]string, 0, len(dirs)+2)
	for _, dir := range dirs {
		candidates = append(candidates, filepath.Join(dir, binary))
	}
	if unixAgentAppBundleGOOS == "darwin" {
		if relative := unixAgentAppBundleBinaries[binary]; relative != "" {
			candidates = append(candidates,
				filepath.Join(home, "Applications", relative),
				filepath.Join("/Applications", relative),
			)
		}
	}
	return candidates
}

// unixAgentAppBundleBinaries are CLIs that macOS installs inside an app
// bundle. Kiro CLI.app keeps kiro-cli in Contents/MacOS, and a bin
// directory links to it only after the user runs the app's shell setup.
// Until then the user can still start the bundle's binary, so discovery
// looks in the bundle too: the user's ~/Applications first, then
// /Applications.
var unixAgentAppBundleBinaries = map[string]string{
	"kiro-cli": filepath.Join("Kiro CLI.app", "Contents", "MacOS", "kiro-cli"),
}

// unixAgentAppBundleGOOS selects the app bundle candidates; tests set it.
var unixAgentAppBundleGOOS = runtime.GOOS

// UnixAgentSearchDirs lists fixed directories agent discovery looks in for
// home, per-user install locations first, then the machine prefixes. It
// never touches the filesystem, so a root parent can use it to build the
// worker's PATH. The standalone profile adds the fixed bin and shim
// directories of Volta, pnpm, yarn, fnm, asdf, mise and Linuxbrew.
func UnixAgentSearchDirs(home string) []string {
	return append(unixUserAgentBinDirs(home, false), unixMachineAgentBinDirs()...)
}

// UnixAgentSearchDirsFor is UnixAgentSearchDirs for account uid. In the
// standalone profile it leaves out a machine directory outside the home
// that unixPathTrustedFor does not admit for uid, as discovery does, so the
// per-user worker never finds an agent there that another account could
// have replaced.
func UnixAgentSearchDirsFor(home string, uid int) []string {
	dirs := unixUserAgentBinDirs(home, false)
	for _, dir := range unixMachineAgentBinDirs() {
		if StandaloneUnix() && !unixPathTrustedFor(dir, uid) {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// unixAgentDiscoveryDirs adds, for the per-user worker, the bin directories
// found by reading the home: the npm prefix in ~/.npmrc and each installed
// Node of nvm, fnm, asdf and mise.
func unixAgentDiscoveryDirs(home string) []string {
	return append(unixUserAgentBinDirs(home, unixUserDiscoveryExtended()), unixMachineAgentBinDirs()...)
}

func unixUserAgentBinDirs(home string, readHome bool) []string {
	dirs := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".npm-global", "bin"),
		filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".opencode", "bin"),
		filepath.Join(home, "bin"),
	}
	if !StandaloneUnix() {
		return dirs
	}
	if readHome {
		if prefix := userNPMRCPrefix(home); prefix != "" {
			dirs = append(dirs, filepath.Join(prefix, "bin"))
		}
	}
	dirs = append(dirs,
		filepath.Join(home, ".npm-packages", "bin"),
		filepath.Join(home, ".volta", "bin"),
		filepath.Join(home, ".local", "share", "pnpm"),
		filepath.Join(home, "Library", "pnpm"),
		filepath.Join(home, ".yarn", "bin"),
		filepath.Join(home, ".config", "yarn", "global", "node_modules", ".bin"),
		filepath.Join(home, ".local", "share", "fnm", "aliases", "default", "bin"),
		filepath.Join(home, ".asdf", "shims"),
		filepath.Join(home, ".local", "share", "mise", "shims"),
	)
	if readHome {
		for _, pattern := range userVersionedNodePrefixPatterns(home) {
			if strings.Contains(pattern, "pnpm") {
				continue // pnpm's global dirs hold packages, not binaries
			}
			for _, prefix := range newestVersionedDirs(pattern, unixVersionedPrefixLimit) {
				dirs = append(dirs, filepath.Join(prefix, "bin"))
			}
		}
	}
	return append(dirs,
		filepath.Join(home, ".linuxbrew", "bin"),
		"/home/linuxbrew/.linuxbrew/bin",
	)
}

func unixMachineAgentBinDirs() []string {
	var dirs []string
	for _, prefix := range machinePrefixes() {
		dirs = append(dirs, filepath.Join(prefix, "bin"))
	}
	return dirs
}

// readUVToolVersion reads the version of distribution dist from the default
// `uv tool install` environment of tool under home (OpenHands needs about
// 11 s to answer --version, beyond the probe timeout).
func readUVToolVersion(home, tool, dist string) string {
	pattern := filepath.Join(home, ".local", "share", "uv", "tools", tool, "lib", "python*", "site-packages", dist+"-*.dist-info")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) != 1 {
		return ""
	}
	info, err := os.Lstat(matches[0])
	if err != nil || !info.IsDir() {
		return ""
	}
	version := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(matches[0]), dist+"-"), ".dist-info")
	if !validUnixAgentVersion(version) {
		return ""
	}
	return version
}

// readUnixInstallStampVersion reads the release from a bounded install
// stamp: its displayVersion ("0.21.5+8332.g3d304a1", the form --version
// prints) or, when that is not a usable version, its baseVersion.
func readUnixInstallStampVersion(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil || len(data) > unixAgentVersionMaxBytes {
		return ""
	}
	var stamp struct {
		DisplayVersion string `json:"displayVersion"`
		BaseVersion    string `json:"baseVersion"`
	}
	if json.Unmarshal(data, &stamp) != nil {
		return ""
	}
	for _, version := range []string{strings.TrimSpace(stamp.DisplayVersion), strings.TrimSpace(stamp.BaseVersion)} {
		if validUnixAgentVersion(version) {
			return version
		}
	}
	return ""
}

type unixPackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readUnixPackageVersion reads a bounded package.json. When requireRoot is
// set every path element must be root-owned and not group/other writable.
func readUnixPackageVersion(path, wantName string, requireRoot bool) (string, bool) {
	if requireRoot && !rootOwnedChain(path) {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil || len(data) > unixAgentVersionMaxBytes {
		return "", false
	}
	var parsed unixPackageJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", false
	}
	if wantName != "" && strings.TrimSpace(parsed.Name) != wantName {
		return "", false
	}
	version := strings.TrimSpace(parsed.Version)
	if !validUnixAgentVersion(version) {
		return "", false
	}
	return version, true
}

// unixDiscoveryUID is the account discovery reads and runs agent files for:
// the per-user worker runs with the target user's credentials. Tests
// replace it.
var unixDiscoveryUID = os.Geteuid

// unixDiscoveryCandidateTrusted reports whether discovery may read or run
// path for the target user. Files inside the user's home are the user's own.
// A candidate outside the home (the machine prefixes, agent_prefixes, the
// shared Linuxbrew prefix, an npm prefix set outside the home), or a home
// entry that links out of the home, is used only when unixPathTrustedFor
// admits it for the target uid.
func unixDiscoveryCandidateTrusted(home, path string) bool {
	uid := unixDiscoveryUID()
	home = filepath.Clean(home)
	if !pathInside(home, path) {
		return unixPathTrustedFor(path, uid)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true // nothing there to run or read
	}
	if pathInside(home, resolved) {
		return true
	}
	if realHome, err := filepath.EvalSymlinks(home); err == nil && pathInside(realHome, resolved) {
		return true
	}
	return unixPathTrustedFor(resolved, uid)
}

// darwinAdminGroupGID is the macOS admin group. Its members can already act
// as root through sudo, so a folder they may write (/Applications,
// root:admin 0775, or a Homebrew prefix an administrator owns) lets no
// account change a path that it could not change as root anyway.
const darwinAdminGroupGID = 80

// unixPathTrustAdminGroup returns the group whose write access
// unixPathTrustedFor accepts, and whether there is one: the admin group on
// macOS, none on Linux (Linuxbrew and similar shared prefixes stay strict).
// A seam for tests.
var unixPathTrustAdminGroup = func() (uint32, bool) {
	return darwinAdminGroupGID, runtime.GOOS == "darwin"
}

// unixAdminGroupMember reports whether account uid is a member of group
// gid. A seam for tests.
var unixAdminGroupMember = func(uid, gid uint32) bool {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	groups, err := account.GroupIds()
	if err != nil {
		return false
	}
	want := strconv.FormatUint(uint64(gid), 10)
	for _, group := range groups {
		if group == want {
			return true
		}
	}
	return false
}

// UnixPathTrustedFor is unixPathTrustedFor for callers outside this package.
func UnixPathTrustedFor(path string, uid int) bool { return unixPathTrustedFor(path, uid) }

// unixPathTrustedFor resolves path one element at a time, following
// symbolic links as the kernel does, and admits it only when every
// directory it passes through, every link it follows and the final entry
// are owned by root or uid, and no directory or final entry is writable by
// group or others. No other account can then change what path names
// between the check and its use. On macOS an element of the admin group
// that others cannot write is also admitted when root, uid or an admin
// member owns it (unixPathTrustAdminGroup).
func unixPathTrustedFor(path string, uid int) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	const maxLinks = 40
	adminGID, adminGroup := unixPathTrustAdminGroup()
	adminMembers := map[uint32]bool{}
	adminMember := func(owner uint32) bool {
		member, seen := adminMembers[owner]
		if !seen {
			member = unixAdminGroupMember(owner, adminGID)
			adminMembers[owner] = member
		}
		return member
	}
	// trusted checks the owner and, for a directory or final entry
	// (checkMode), the write bits.
	trusted := func(info os.FileInfo, checkMode bool) bool {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		ownerTrusted := st.Uid == 0 || int64(st.Uid) == int64(uid)
		perm := info.Mode().Perm()
		if ownerTrusted && (!checkMode || perm&0o022 == 0) {
			return true
		}
		return adminGroup && st.Gid == adminGID && (!checkMode || perm&0o002 == 0) &&
			(ownerTrusted || adminMember(st.Uid))
	}
	root, err := os.Lstat("/")
	if err != nil || !trusted(root, true) {
		return false
	}
	current := "/"
	pending := strings.Split(filepath.Clean(path), "/")
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			// current is always a verified directory reached from "/", so
			// its parent was verified on the way down.
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, name)
		info, err := os.Lstat(next)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if !trusted(info, false) {
				return false
			}
			links++
			target, err := os.Readlink(next)
			if err != nil || target == "" || links > maxLinks {
				return false
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if !trusted(info, true) {
			return false
		}
		if len(pending) > 0 && !info.IsDir() {
			return false
		}
		current = next
	}
	return true
}

func rootOwnedChain(path string) bool {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if current == filepath.Dir(current) {
			return true
		}
	}
}

// newestVersionDir returns the highest semver-named child of dir.
func newestVersionDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var versions []string
	for _, entry := range entries {
		name := entry.Name()
		if validUnixAgentVersion(name) {
			versions = append(versions, name)
		}
		if len(versions) > 256 {
			break
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Slice(versions, func(i, j int) bool { return compareUnixVersions(versions[i], versions[j]) < 0 })
	return versions[len(versions)-1]
}

func compareUnixVersions(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		core := v
		if i := strings.IndexAny(core, "+-"); i >= 0 {
			core = core[:i]
		}
		for i, part := range strings.SplitN(core, ".", 3) {
			n, _ := strconv.Atoi(part)
			out[i] = n
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

func validUnixAgentVersion(version string) bool {
	if version == "" || len(version) > unixAgentVersionMaxRunes {
		return false
	}
	return unixAgentSemver.MatchString(version)
}

// ValidUnixAgentVersion reports whether version is a bounded, semver-like
// agent version exactly as discovery accepts it from package metadata. The
// root parent re-validates the worker's user-influenced answers with it.
func ValidUnixAgentVersion(version string) bool {
	return validUnixAgentVersion(version)
}

// ExtractUnixAgentVersion takes the first semver-looking token of a
// `--version` first line ("codex-cli 0.142.0", "2.1.187 (Claude Code)",
// "v1.4.2"). Only surrounding punctuation and a leading "v" are removed, so
// a prerelease that ends in "v" ("1.2.0-dev") keeps its last letter.
func ExtractUnixAgentVersion(line string) string {
	fields := strings.Fields(line)
	for i := range fields {
		token := strings.Trim(fields[i], "()[],")
		token = strings.Trim(strings.TrimPrefix(token, "v"), "()[],")
		if validUnixAgentVersion(token) {
			return token
		}
	}
	return ""
}

var errUnixAgentVersionOutput = errors.New("agent --version output exceeds bound")

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		remaining := c.limit - c.buf.Len()
		if remaining > 0 {
			c.buf.Write(p[:remaining])
		}
		return 0, errUnixAgentVersionOutput
	}
	return c.buf.Write(p)
}

// unixAgentVersionAttemptTimeout bounds one `--version` run; tests shorten
// it.
var unixAgentVersionAttemptTimeout = unixAgentVersionTimeout

// execUnixAgentVersion runs candidate --version with a minimal environment
// and a timeout. The caller must already run as the target user. A run that
// times out is retried once at once: a cold start right after install, when
// the enumerator probes every connector for every user together, can take
// most of the timeout (agy took 4.85 s cold and 0.15 s warm), and the next
// cycle is five minutes away.
func execUnixAgentVersion(ctx context.Context, candidate, home, stateEnv string) string {
	info, err := os.Stat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; attempt < 2; attempt++ {
		version, timedOut := runUnixAgentVersion(ctx, candidate, home, stateEnv)
		if version != "" || !timedOut || ctx.Err() != nil {
			return version
		}
	}
	return ""
}

// runUnixAgentVersion is one `--version` run; timedOut reports that it hit
// its own timeout.
func runUnixAgentVersion(parent context.Context, candidate, home, stateEnv string) (version string, timedOut bool) {
	ctx, cancel := context.WithTimeout(parent, unixAgentVersionAttemptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, candidate, "--version")
	cmd.Dir = home
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + filepath.Dir(candidate) + ":/usr/bin:/bin",
		"LANG=C",
		"NO_COLOR=1",
		"TERM=dumb",
		"CI=1",
	}
	if stateEnv != "" {
		scratch, err := os.MkdirTemp("", "dc-agent-probe-")
		if err != nil {
			return "", false
		}
		defer os.RemoveAll(scratch)
		cmd.Env = append(cmd.Env, stateEnv+"="+scratch, "TMPDIR="+scratch)
	}
	out := &cappedBuffer{limit: unixAgentVersionOutput}
	errOut := &cappedBuffer{limit: unixAgentVersionOutput}
	cmd.Stdout = out
	// Some agents (Hermes) print their version on stderr when stdout is
	// not a terminal; read it only when stdout names no version.
	cmd.Stderr = errOut
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	_ = cmd.Run()
	first, _, _ := strings.Cut(out.buf.String(), "\n")
	if version := ExtractUnixAgentVersion(first); version != "" {
		return version, false
	}
	first, _, _ = strings.Cut(errOut.buf.String(), "\n")
	return ExtractUnixAgentVersion(first), errors.Is(ctx.Err(), context.DeadlineExceeded)
}
