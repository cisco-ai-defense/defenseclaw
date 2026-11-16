// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Claude Desktop runs Claude Cowork and its Code tab with a Claude Code
// engine build it keeps in its own data folder, in the user's home, one
// folder per deployment (internal/claudedesktop lists them):
//
//	macOS  ~/Library/Application Support/Claude/claude-code/<version>/<build>/claude.app/Contents/MacOS/claude
//	       ~/Library/Application Support/Claude-3p/claude-code/... (third-party inference)
//	Linux  ~/.config/Claude/claude-code/<version>/... (and ~/.config/Claude-3p)
//
// (macOS measured on Claude Desktop 4.4212.0 with engine 2.1.309 and on
// 4.16336.0 with engine 2.1.317 for both deployments; the Linux folders
// are a live check.) The user can write that folder, so neither its owner nor its
// layout identifies the build. On macOS the build is trusted by its code
// signature instead (owner decision for 1.0.8): a strict codesign verify
// with Anthropic's Developer ID team and the Claude Code signing
// identifier, run as the session's account, with the executable and the
// sealed Info.plist pinned for the duration of the check, and the version
// in the folder name must be the version that Info.plist names. Linux
// builds carry no vendor signature, so a Linux engine build stays an
// unidentified, user-writable engine, as before.

// Launch coverage reasons for a running Claude Desktop engine build.
const (
	reasonClaudeDesktopUnsigned        = "claude_desktop_engine_unsigned"
	reasonClaudeDesktopLinuxUnsigned   = "claude_desktop_engine_linux_unsigned"
	reasonClaudeDesktopVersionMismatch = "claude_desktop_engine_version_mismatch"
)

// verifyClaudeDesktopEngine checks a macOS engine bundle; tests replace it.
var verifyClaudeDesktopEngine = codesig.VerifyDarwin

// claudeDesktopAccountGID is the passwd primary group of the session's
// account (the group codesign runs with); tests replace it.
var claudeDesktopAccountGID = func(uid int) (uint32, bool) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, false
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	return uint32(gid), err == nil
}

// claudeDesktopEngine is a running build in Claude Desktop's engine folder.
type claudeDesktopEngine struct {
	goos    string
	version string
	// bundle, executable and plist are the macOS app bundle, its main
	// executable and its Info.plist; empty on Linux.
	bundle, executable, plist string
}

// claudeDesktopEngineBuild recognizes a running executable as a build in
// Claude Desktop's engine folder of home, the session account's home.
func claudeDesktopEngineBuild(goos, home, executable string) (claudeDesktopEngine, bool) {
	exe := claudeRunningExecutable(executable)
	if exe.path == "" || exe.replaced || home == "" || !filepath.IsAbs(home) {
		return claudeDesktopEngine{}, false
	}
	homes := []string{filepath.Clean(home)}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && resolved != homes[0] {
		homes = append(homes, resolved)
	}
	rest, ok := "", false
	for _, root := range homes {
		if rest, ok = claudedesktop.CutEngineDir(goos, claudedesktop.FoldersForHome(goos, root), exe.path); ok {
			break
		}
	}
	if !ok {
		return claudeDesktopEngine{}, false
	}
	parts := strings.Split(rest, string(filepath.Separator))
	if len(parts) < 2 || len(parts) > 8 || !enterprisehooks.ValidUnixAgentVersion(parts[0]) {
		return claudeDesktopEngine{}, false
	}
	engine := claudeDesktopEngine{goos: goos, version: parts[0]}
	if goos != "darwin" {
		return engine, true
	}
	// <version>/[<build>/]claude.app/Contents/MacOS/claude
	tail := parts[1:]
	if len(tail) == 5 {
		tail = tail[1:]
	}
	if strings.Join(tail, "/") != "claude.app/Contents/MacOS/claude" {
		return claudeDesktopEngine{}, false
	}
	engine.bundle = filepath.Dir(filepath.Dir(filepath.Dir(exe.path)))
	engine.executable = exe.path
	engine.plist = filepath.Join(engine.bundle, "Contents", "Info.plist")
	return engine, true
}

// claudeDesktopVerdict is the launch coverage of one engine build: a reason
// code ("" when covered) and its detail for the message. unsigned says the
// build carries no signature at all (status reports it as unsigned rather
// than untrusted).
type claudeDesktopVerdict struct {
	reason, detail string
	unsigned       bool
}

// claudeDesktopVerdictFor is claudeDesktopEngineCoverage once per engine
// build and account in one status or verify run: every Cowork turn is a
// session of its own, and they share a build.
func (l *lifecycle) claudeDesktopVerdictFor(ctx context.Context, engine claudeDesktopEngine, uid int) claudeDesktopVerdict {
	key := engine.goos + "\x00" + engine.executable + "\x00" + engine.version + "\x00" + strconv.Itoa(uid)
	if verdict, ok := l.claudeDesktopVerdicts[key]; ok {
		return verdict
	}
	verdict := claudeDesktopEngineCoverage(ctx, engine, uid)
	if l.claudeDesktopVerdicts == nil {
		l.claudeDesktopVerdicts = map[string]claudeDesktopVerdict{}
	}
	l.claudeDesktopVerdicts[key] = verdict
	return verdict
}

// claudeDesktopEngineCoverage names why a running Claude Desktop engine
// build is not proven to run a release with a verified managed hook
// contract, or "" when it is. uid is the session's account.
func claudeDesktopEngineCoverage(ctx context.Context, engine claudeDesktopEngine, uid int) claudeDesktopVerdict {
	if engine.goos != "darwin" {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopLinuxUnsigned}
	}
	// codesign runs as the session's account with its passwd primary group
	// (codesig drops every supplementary group), never as root: a session
	// whose account is not known stays unverified.
	if uid <= 0 {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopUnsigned, detail: "session account unknown"}
	}
	gid, ok := claudeDesktopAccountGID(uid)
	if !ok || gid == 0 {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopUnsigned, detail: "session account unknown"}
	}
	if info, err := os.Lstat(engine.bundle); err != nil || !info.IsDir() {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopUnsigned, detail: "the engine bundle cannot be read"}
	}
	if plistVersion := claudeDesktopPlistVersion(engine.plist); plistVersion != engine.version {
		detail := "its Info.plist names no version"
		if plistVersion != "" {
			detail = "its Info.plist names " + plistVersion
		}
		return claudeDesktopVerdict{reason: reasonClaudeDesktopVersionMismatch, detail: "the build runs from the " + engine.version + " folder, but " + detail}
	}
	signature := verifyClaudeDesktopEngine(ctx, engine.bundle, codesig.ClaudeCodeDarwin,
		codesig.DarwinOptions{Pin: []string{engine.executable, engine.plist}, UID: uint32(uid), GID: gid})
	if !signature.Verified {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopUnsigned, detail: signature.Reason, unsigned: signature.Unsigned}
	}
	// The pinned Info.plist was not changed during the check, and the
	// signature seals it: read the version again to bind it to that file.
	if claudeDesktopPlistVersion(engine.plist) != engine.version {
		return claudeDesktopVerdict{reason: reasonClaudeDesktopVersionMismatch, detail: "its Info.plist changed after the signature check"}
	}
	if connector.ResolveHookContract("claudecode", engine.version).Status != connector.HookCompatibilityKnown {
		return claudeDesktopVerdict{reason: "claude_version_unverified"}
	}
	return claudeDesktopVerdict{}
}

var claudeDesktopPlistShortVersion = lazyregexp.New(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,64})</string>`)

// claudeDesktopPlistVersion reads an engine bundle's XML Info.plist
// CFBundleShortVersionString without following a link or blocking on a FIFO
// (the file is in a user's folder and status runs as root), or "".
func claudeDesktopPlistVersion(path string) string {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	const maxPlistBytes = 64 << 10
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPlistBytes {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPlistBytes+1))
	if err != nil || len(data) > maxPlistBytes {
		return ""
	}
	match := claudeDesktopPlistShortVersion.FindSubmatch(data)
	if match == nil {
		return ""
	}
	version := strings.TrimSpace(string(match[1]))
	if !enterprisehooks.ValidUnixAgentVersion(version) {
		return ""
	}
	return version
}
