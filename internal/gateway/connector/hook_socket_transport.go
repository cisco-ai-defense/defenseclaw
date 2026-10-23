// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"strconv"
	"strings"
)

// shellHookSocketTrustFunctions names the standalone hook socket and
// defines defenseclaw_hook_socket_trusted, which a bash script calls before
// it sends anything to the socket.
const shellHookSocketTrustFunctions = `# Standalone enterprise transport. This hook reaches the gateway only
# through its peer-authorized unix hook socket, never the loopback TCP port:
# another local user can hold that port while the gateway restarts, and the
# TCP bearer is shared by every user of this connector. No standard user can
# create a socket in a directory that belongs to root or the gateway account
# and that no one else can write, so a verified path cannot lead to another
# user's listener. The gateway identifies this caller by its kernel-verified
# uid, so no bearer is sent.
DEFENSECLAW_HOOK_SOCKET=@SOCKET@
DEFENSECLAW_HOOK_SOCKET_UID=@UID@
defenseclaw_hook_socket_owner_trusted() {
  [ "$1" = "0" ] || { [ "$DEFENSECLAW_HOOK_SOCKET_UID" != "0" ] && [ "$1" = "$DEFENSECLAW_HOOK_SOCKET_UID" ]; }
}
defenseclaw_hook_socket_directory_trusted() {
  local socket_dir listing mode owner
  socket_dir="${DEFENSECLAW_HOOK_SOCKET%/*}"
  [ -n "$socket_dir" ] || socket_dir=/
  socket_dir="$(cd -P -- "$socket_dir" 2>/dev/null && pwd -P)" || return 1
  listing="$(command ls -ldn -- "$socket_dir" 2>/dev/null)" || return 1
  read -r mode _ owner _ <<< "$listing" || return 1
  case "$mode" in
    d????-??-*) ;;
    *) return 1 ;;
  esac
  defenseclaw_hook_socket_owner_trusted "$owner"
}
defenseclaw_hook_socket_trusted() {
  local listing mode owner
  { [ -S "$DEFENSECLAW_HOOK_SOCKET" ] && [ ! -L "$DEFENSECLAW_HOOK_SOCKET" ]; } || return 1
  defenseclaw_hook_socket_directory_trusted || return 1
  listing="$(command ls -ln -- "$DEFENSECLAW_HOOK_SOCKET" 2>/dev/null)" || return 1
  read -r mode _ owner _ <<< "$listing" || return 1
  case "$mode" in
    s*) ;;
    *) return 1 ;;
  esac
  defenseclaw_hook_socket_owner_trusted "$owner"
}
`

// shellHookSocketTransportBlock is inserted into a connector shell hook,
// immediately before it builds its bearer header, when the hook is a
// standalone enterprise install with a unix hook socket (see
// managedPluginHookSocket). fail_unreachable is already defined at that
// point. The rendered TCP hook contains none of this. @GUARD@ is the
// standalone Hermes foreign-hook guard
// (shellHookForeignGuard), or nothing: it runs after the trust functions it
// uses and before the socket checks, because a missing or untrusted socket
// ends the hook before a request is sent. Only a missing socket in a trusted
// directory can follow administrator open; an untrusted or failed existing
// socket blocks in every mode.
// The guard's check denies a guarded connector whose session the gateway
// cannot answer for, in every fail mode (GAP-0354).
const shellHookSocketTransportBlock = shellHookSocketTrustFunctions + `@GUARD@if ! defenseclaw_hook_socket_directory_trusted; then
  FAIL_MODE=closed
  fail_unreachable "the DefenseClaw hook socket directory is not owned by root or the gateway account (enterprise_managed_gateway_peer_unverified)"
fi
if [ ! -e "$DEFENSECLAW_HOOK_SOCKET" ] && [ ! -L "$DEFENSECLAW_HOOK_SOCKET" ]; then
  fail_unreachable "` + shellManagedGatewayStoppedText + `"
fi
# The path existed. From here, a refusal or a disappeared socket cannot
# prove that the gateway service is stopped, so delivery failures close.
FAIL_MODE=closed
if ! defenseclaw_hook_socket_trusted; then
  fail_unreachable "the DefenseClaw hook socket or its directory is not owned by root or the gateway account (enterprise_managed_gateway_peer_unverified)"
fi
API_TOKEN=
@FACTS@
`

// shellManagedGatewayStoppedText is what a standalone shell hook says when
// its hook socket is missing (the gateway service and its socket unit are
// stopped), in the words the native hook uses for a stopped gateway service.
// The socket-ownership text is only for a socket that exists with the wrong
// owner (GAP-0581).
const shellManagedGatewayStoppedText = "the DefenseClaw gateway service is not running on this computer. " +
	"Try again in a moment; if this continues, ask your administrator to start the DefenseClaw gateway service. " +
	"(enterprise_managed_gateway_not_running)"

// shellHookSocketTransport renders shellHookSocketTransportBlock for the
// socket path and the gateway service uid trusted beside root. The path is
// emitted as one single-quoted shell word, so no character in it can end
// the assignment. factsBinary, when set, is the administrator-owned hook
// binary the hook runs (hook session-facts) to read the user's Kerberos
// credential cache, which a shell cannot read; see managedSessionFactsBinary.
// guard is the rendered foreign-hook guard block, or "" for every hook but
// the standalone Hermes one; with "" the block renders as it did before the
// guard moved into it.
func shellHookSocketTransport(socket string, serviceUID int, factsBinary, guard string) string {
	facts := ""
	if factsBinary != "" {
		facts = "DEFENSECLAW_SESSION_FACTS_BIN=" + shellSingleQuote(factsBinary) + "\nexport DEFENSECLAW_SESSION_FACTS_BIN\n"
	}
	block := strings.Replace(renderShellHookSocket(shellHookSocketTransportBlock, socket, serviceUID), "@FACTS@", facts, 1)
	return strings.Replace(block, "@GUARD@", guard, 1)
}

// managedSessionFactsBinary is the administrator-owned hook binary a managed
// standalone shell hook runs for the session facts, or "" when the install
// has none. It is the install's hook binary, whatever the connector: it is
// root-owned and serves `hook session-facts` like the per-user gateway
// binary does (GAP-0194). It does not depend on the foreign-hook guard,
// which only some connectors run.
func managedSessionFactsBinary(opts SetupOpts) string {
	binary := strings.TrimSpace(opts.ManagedHookBinary)
	if !opts.ManagedEnterprise || binary == "" || !filepath.IsAbs(binary) || strings.ContainsAny(binary, "\x00\r\n") {
		return ""
	}
	return filepath.Clean(binary)
}

// shellHookSocketTrust renders shellHookSocketTrustFunctions for scripts
// that decide themselves what to do with an untrusted socket (the Codex
// notify bridge drops the event, as it does when the gateway is down).
func shellHookSocketTrust(socket string, serviceUID int) string {
	return renderShellHookSocket(shellHookSocketTrustFunctions, socket, serviceUID)
}

func renderShellHookSocket(block, socket string, serviceUID int) string {
	if serviceUID < 0 {
		serviceUID = 0
	}
	block = strings.Replace(block, "@SOCKET@", shellSingleQuote(socket), 1)
	return strings.Replace(block, "@UID@", strconv.Itoa(serviceUID), 1)
}
