// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// localCommandLinkTwinRequest is a POSIX shell call with each path word that
// a link moves spelled as the place it reaches in this host's file system
// (hookpaths.LocalCommandWordPlaces, hookpaths.LinkResolvedCommand): the call
// as the shell runs it once the kernel has followed its links. Each reader
// follows a link only where it reads the operand itself (cat key-link reads
// the key; the AWS, agent-config and shell-profile path rules and the hook
// config guard read the word as written), so a link operand behind a wrapper
// (command cat key-link), in the input of a loop, in a descriptor redirect,
// a write through a linked file (echo x > cfg-link, cp /tmp/x cfg-link) or an
// upload (scp key-link host:) got the verdict of an ordinary file
// (rel-1-0-10:GAP-1243). trustedToolCallFindings judges the twin with every
// reading of the call, and its findings only add to the call's. A call whose
// words name no link has no twin.
//
// The gateway walks only the file system it shares with the call: not for a
// Substrate actor or a sandbox (SkipLocalFilesystemResolution), not behind
// ProtectHome (the hook client reads the links there), and only for a POSIX
// home on a POSIX host.
func localCommandLinkTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	if request.localLinkTwin || request.SkipLocalFilesystemResolution || request.ProtectedHomeHook ||
		runtime.GOOS == "windows" || !trustedBashExecutionTool(request.Input.Tool) ||
		request.Input.DialectHint != "" && request.Input.DialectHint != actionfacts.DialectPOSIX {
		return trustedActionRequest{}, false
	}
	home, cwd := request.Input.ActiveHome, request.Input.CWD
	if !strings.HasPrefix(home, "/") || !filepath.IsAbs(cwd) {
		return trustedActionRequest{}, false
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok {
		return trustedActionRequest{}, false
	}
	places := hookpaths.LocalCommandWordPlaces(command, cwd, home, request.targetMemo.ResolveWriteTarget)
	resolved, changed := hookpaths.LinkResolvedCommand(command, home, places)
	if !changed {
		return trustedActionRequest{}, false
	}
	twin := bashReadingRequest(request, command, resolved)
	twin.localLinkTwin = true
	return twin, true
}
