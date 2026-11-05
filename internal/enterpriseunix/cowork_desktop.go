// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Claude Code is a machine-policy connector on Linux and macOS: an account
// whose only Claude Code is Claude Desktop (Cowork) gets no enrollment row,
// and the engine's trust was decided only for a running engine (launch
// coverage). describeCoworkDesktop reads, for every account enrollment
// includes, the Claude Desktop data folders (internal/claudedesktop, 1p and
// 3p), the newest engine build in each and its trust, from disk, as status
// or verify runs (cowork-1-0-8 GAP-0031). It is read-only and bounded: it
// lists known folders without following links, reads the build's Info.plist
// and, on macOS, runs codesign as the account (claudeDesktopEngineCoverage,
// the check launch coverage uses); it never runs the engine.

// coworkDesktopBudget bounds the engine checks of one status or verify run.
var coworkDesktopBudget = 60 * time.Second

const (
	// coworkDesktopVersionsMax bounds the entries read from one engine folder.
	coworkDesktopVersionsMax = 256
	// coworkDesktopBundlesMax bounds the engine bundles checked in one
	// version folder (<version>/claude.app or <version>/<build>/claude.app).
	coworkDesktopBundlesMax = 4
)

// coworkDesktopAccount is an account enrollment includes.
type coworkDesktopAccount struct {
	user, home string
	uid        int
}

// describeCoworkDesktop is the claude_desktop member of the cowork block.
// targets are the enumerator's manifest rows; cfg is the installed config
// (nil when it could not be read).
func (l *lifecycle) describeCoworkDesktop(ctx context.Context, cfg *config.Config, targets []enterprisehooks.ManifestTarget) *enterprisestatus.CoworkDesktopState {
	accounts, known := l.coworkDesktopAccounts(cfg, targets)
	state := &enterprisestatus.CoworkDesktopState{AccountsKnown: known}
	if len(accounts) > enterprisestatus.CoworkAccountsMax {
		accounts, state.AccountsTruncated = accounts[:enterprisestatus.CoworkAccountsMax], true
	}
	ctx, cancel := context.WithTimeout(ctx, coworkDesktopBudget)
	defer cancel()
	for _, account := range accounts {
		entry := enterprisestatus.CoworkDesktopAccount{Account: account.user, Installs: l.coworkDesktopInstalls(ctx, account)}
		for _, install := range entry.Installs {
			state.Count(install)
		}
		state.Accounts = append(state.Accounts, entry)
	}
	return state
}

// coworkEligibleAccounts is enterprisehooks.LoadUnixEligibleAccounts, which
// refuses a record that is not a root-owned 0600 single-link file below a
// root-owned folder chain; tests replace it.
var coworkEligibleAccounts = enterprisehooks.LoadUnixEligibleAccounts

// coworkManifestEnrollment reports whether only the manifest decides which
// accounts enrollment includes: manifest enrollment, or unenrolled_users
// deny (the rule copilotAccountHomes applies).
func coworkManifestEnrollment(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	enrollment := cfg.Enterprise.Enrollment
	return strings.EqualFold(strings.TrimSpace(enrollment.Mode), config.EnterpriseEnrollmentManifest) ||
		strings.EqualFold(strings.TrimSpace(enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny)
}

// coworkDesktopAccounts are the accounts enrollment includes, by name: the
// accounts the enumerator found eligible (eligible-accounts.json) and the
// enabled manifest rows. Under manifest enrollment the enumerator is idle,
// so the record is what its last auto pass published: there only eligible
// accounts an enabled manifest row names count (ManifestEnrolledAccounts,
// GAP-0761), or status would list, and run codesign as, an account the
// administrator has since left out. known is false when the record exists
// but is refused or cannot be read.
func (l *lifecycle) coworkDesktopAccounts(cfg *config.Config, targets []enterprisehooks.ManifestTarget) ([]coworkDesktopAccount, bool) {
	env := l.env
	byName := map[string]coworkDesktopAccount{}
	add := func(user, home string, uid int) {
		user, home = strings.TrimSpace(user), strings.TrimSpace(home)
		if _, seen := byName[user]; seen || user == "" || uid <= 0 || !filepath.IsAbs(home) {
			return
		}
		byName[user] = coworkDesktopAccount{user: user, home: filepath.Clean(home), uid: uid}
	}
	var enabled []enterprisehooks.ManifestTarget
	for _, target := range targets {
		if target.IsEnabled() {
			enabled = append(enabled, target)
		}
	}
	known := true
	path := env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath))
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		eligible, err := coworkEligibleAccounts(path)
		known = err == nil
		if coworkManifestEnrollment(cfg) {
			eligible = enterprisehooks.ManifestEnrolledAccounts(eligible, enterprisehooks.Manifest{Targets: enabled})
		}
		for _, account := range eligible {
			add(account.User, account.Home, account.UID)
		}
	}
	for _, target := range enabled {
		if target.UID != nil {
			add(target.User, target.UserHome, *target.UID)
		}
	}
	accounts := make([]coworkDesktopAccount, 0, len(byName))
	for _, account := range byName {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].user < accounts[j].user })
	return accounts, known
}

// coworkDesktopInstalls are the account's Claude Desktop data folders that
// exist, each with its newest engine build and that build's trust.
func (l *lifecycle) coworkDesktopInstalls(ctx context.Context, account coworkDesktopAccount) []enterprisestatus.CoworkDesktopInstall {
	env := l.env
	goos := env.GOOS
	var out []enterprisestatus.CoworkDesktopInstall
	// macOS and Linux roots hold no "*", so nothing overflows here.
	dirs, _ := claudedesktop.DataDirs(goos, claudedesktop.FoldersForHome(goos, account.home))
	for _, dir := range dirs {
		if strings.Contains(dir.Root.Path, "*") || !coworkDesktopRealDir(env.P(account.home), env.P(dir.Path)) {
			continue
		}
		install := enterprisestatus.CoworkDesktopInstall{Deployment: string(dir.Root.Deployment), Path: dir.Path, Trust: enterprisestatus.CoworkEngineNotFound}
		engineDir := filepath.Join(dir.Path, claudedesktop.EngineFolder)
		version := coworkDesktopNewestVersion(env.P(engineDir))
		if version == "" {
			out = append(out, install)
			continue
		}
		install.EngineVersion = version
		versionDir := filepath.Join(engineDir, version)
		install.EnginePath = versionDir
		if goos != "darwin" {
			// A Linux build is there only when its folder holds an
			// executable engine; even then it is unsigned
			// (claudedesktop.LinuxEngineExecutable).
			executable := claudedesktop.LinuxEngineExecutable(env.P(versionDir))
			if executable == "" {
				install.Trust, install.Reason = enterprisestatus.CoworkEngineUntrusted, "no executable claude engine in the "+version+" folder"
				out = append(out, install)
				continue
			}
			install.EnginePath = env.canonical(executable)
			install.Trust, install.Reason = coworkEngineTrust(l.claudeDesktopVerdictFor(ctx, claudeDesktopEngine{goos: goos, version: version}, account.uid))
			out = append(out, install)
			continue
		}
		bundles := coworkDesktopBundles(env.P(versionDir))
		if len(bundles) == 0 {
			install.Trust, install.Reason = enterprisestatus.CoworkEngineUntrusted, "no claude.app engine bundle in the "+version+" folder"
		}
		for _, bundle := range bundles {
			if ctx.Err() != nil {
				install.Trust, install.Reason = enterprisestatus.CoworkEngineUntrusted, "not checked: the time for engine checks of this run was spent"
				break
			}
			engine := claudeDesktopEngine{goos: goos, version: version, bundle: bundle,
				executable: filepath.Join(bundle, "Contents", "MacOS", "claude"), plist: filepath.Join(bundle, "Contents", "Info.plist")}
			install.EnginePath = env.canonical(bundle)
			install.Trust, install.Reason = coworkEngineTrust(l.claudeDesktopVerdictFor(ctx, engine, account.uid))
			if install.Trust == enterprisestatus.CoworkEngineTrusted {
				break
			}
		}
		out = append(out, install)
	}
	return out
}

// coworkEngineTrust is the trust result of a launch-coverage verdict.
func coworkEngineTrust(verdict claudeDesktopVerdict) (trust, reason string) {
	switch verdict.reason {
	case "":
		return enterprisestatus.CoworkEngineTrusted, ""
	case "claude_version_unverified":
		return enterprisestatus.CoworkEngineTrusted, "claude_version_unverified: the signature verifies, but this engine version's managed hook contract is not verified"
	case reasonClaudeDesktopLinuxUnsigned:
		return enterprisestatus.CoworkEngineUnsigned, "Linux engine builds carry no vendor signature, and the folder is the user's own"
	}
	reason = verdict.reason
	if verdict.detail != "" {
		reason += ": " + verdict.detail
	}
	if verdict.unsigned {
		return enterprisestatus.CoworkEngineUnsigned, reason
	}
	return enterprisestatus.CoworkEngineUntrusted, reason
}

// coworkDesktopRealDir reports whether path, below home, is a directory
// reached without a symbolic link.
func coworkDesktopRealDir(home, path string) bool {
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	current := home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// coworkDesktopEntries lists at most limit entries of dir, which must be a
// directory and not a link.
func coworkDesktopEntries(dir string, limit int) []os.DirEntry {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	file := os.NewFile(uintptr(fd), dir)
	defer file.Close()
	entries, _ := file.ReadDir(limit)
	return entries
}

// coworkDesktopNewestVersion is the highest version-named folder in an
// engine folder, or "".
func coworkDesktopNewestVersion(engineDir string) string {
	newest := ""
	for _, entry := range coworkDesktopEntries(engineDir, coworkDesktopVersionsMax) {
		name := entry.Name()
		if entry.IsDir() && enterprisehooks.ValidUnixAgentVersion(name) &&
			(newest == "" || enterprisehooks.CompareUnixAgentVersions(name, newest) > 0) {
			newest = name
		}
	}
	return newest
}

// coworkDesktopBundles are the engine bundles of a macOS version folder:
// <version>/claude.app, then <version>/<build>/claude.app by name.
func coworkDesktopBundles(versionDir string) []string {
	isBundle := func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.IsDir()
	}
	var bundles []string
	if path := filepath.Join(versionDir, "claude.app"); isBundle(path) {
		bundles = append(bundles, path)
	}
	entries := coworkDesktopEntries(versionDir, coworkDesktopVersionsMax)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if len(bundles) == coworkDesktopBundlesMax {
			break
		}
		if path := filepath.Join(versionDir, entry.Name(), "claude.app"); entry.IsDir() && entry.Name() != "claude.app" && isBundle(path) {
			bundles = append(bundles, path)
		}
	}
	return bundles
}
