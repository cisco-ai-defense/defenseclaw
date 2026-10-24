// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const netstatHeader = "Active Internet connections (including servers)\n" +
	"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs\n"

func netstatRow(local, foreign, state, process string) string {
	return fmt.Sprintf("tcp4       0      0  %-22s %-22s %-11s            0            0  408300  146988 %20s  00002 00000000 0000000000aba2b0 00000080 01000800      2      0 000000\n",
		local, foreign, state, process)
}

// fakeManagedDarwinHost answers launchctl, ps and netstat the way macOS does
// for an ordinary user, who sees every socket's process in netstat but none
// of the gateway account's descriptors in lsof (GAP-1138).
func fakeManagedDarwinHost(t *testing.T, pids []int, uid string, table string) {
	t.Helper()
	previousPrint, previousTable, previousUID := managedDarwinLaunchdPrint, managedDarwinSocketTable, managedDarwinProcessUID
	var calls atomic.Int32
	managedDarwinLaunchdPrint = func(context.Context, string) ([]byte, error) {
		call := int(calls.Add(1)) - 1
		if call >= len(pids) {
			call = len(pids) - 1
		}
		return []byte(fmt.Sprintf("system/com.cisco.defenseclaw.gateway = {\n\tstate = running\n\tpid = %d\n}\n", pids[call])), nil
	}
	managedDarwinSocketTable = func(context.Context) ([]byte, error) { return []byte(table), nil }
	managedDarwinProcessUID = func(context.Context, int) ([]byte, error) { return []byte(uid + "\n"), nil }
	t.Cleanup(func() {
		managedDarwinLaunchdPrint, managedDarwinSocketTable, managedDarwinProcessUID = previousPrint, previousTable, previousUID
	})
}

func TestManagedDarwinPeerVerifiesTheServiceWithoutItsDescriptors(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	gateway := netstatRow("127.0.0.1.18970", "127.0.0.1.55233", "ESTABLISHED", "defenseclaw-gate:4242")
	editorSide := netstatRow("127.0.0.1.55233", "127.0.0.1.18970", "ESTABLISHED", "defenseclaw-acp:5151")
	cases := []struct {
		name    string
		service string
		pids    []int
		uid     string
		table   string
		ok      bool
	}{
		{"standalone gateway", standaloneGatewayLaunchdLabel, []int{4242}, "502", netstatHeader + editorSide + gateway, true},
		{"secure client gateway as root", secureClientGatewayLaunchdLabel, []int{4242}, "0", netstatHeader + gateway, true},
		{"secure client gateway not root", secureClientGatewayLaunchdLabel, []int{4242}, "502", netstatHeader + gateway, false},
		{"another process holds the tuple", standaloneGatewayLaunchdLabel, []int{4242}, "502",
			netstatHeader + netstatRow("127.0.0.1.18970", "127.0.0.1.55233", "ESTABLISHED", "evil:4242 x:6666"), false},
		{"only the editor side", standaloneGatewayLaunchdLabel, []int{4242}, "502", netstatHeader + editorSide, false},
		{"another client tuple", standaloneGatewayLaunchdLabel, []int{4242}, "502",
			netstatHeader + netstatRow("127.0.0.1.18970", "127.0.0.1.55234", "ESTABLISHED", "defenseclaw-gate:4242"), false},
		{"no process column", standaloneGatewayLaunchdLabel, []int{4242}, "502", gateway, false},
		{"restarted during the check", standaloneGatewayLaunchdLabel, []int{4242, 4343}, "502", netstatHeader + gateway, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeManagedDarwinHost(t, tc.pids, tc.uid, tc.table)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			err := verifyManagedConnectedPeer(ctx, client, server, tc.service)
			if tc.ok && err != nil {
				t.Fatalf("verified gateway refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("unverified gateway accepted")
			}
		})
	}
}

// A process name holds spaces; the PID column is counted from the end.
func TestNetstatConnectedPIDReadsAProcessNameWithSpaces(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	table := netstatHeader + netstatRow("127.0.0.1.18970", "127.0.0.1.55233", "ESTABLISHED", "Google Chrome H:777")
	if pid, err := netstatConnectedPID([]byte(table), client, server); err != nil || pid != 777 {
		t.Fatalf("pid = %d, err = %v", pid, err)
	}
}

// Older macOS prints a numeric "pid" column followed by "epid".
func TestNetstatConnectedPIDReadsTheOlderPIDColumn(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	table := "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat shiwat    pid   epid  state    options\n" +
		"tcp4       0      0  127.0.0.1.18970        127.0.0.1.55233        ESTABLISHED 408300 146988   4242      0 0x0002 0x00000000\n"
	if pid, err := netstatConnectedPID([]byte(table), client, server); err != nil || pid != 4242 {
		t.Fatalf("pid = %d, err = %v", pid, err)
	}
}

// The gateway side of the tuple can appear in the table just after connect().
func TestManagedDarwinPeerWaitsForTheGatewaySideOfTheTuple(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	fakeManagedDarwinHost(t, []int{4242}, "502", "")
	var reads atomic.Int32
	managedDarwinSocketTable = func(context.Context) ([]byte, error) {
		if reads.Add(1) < 3 {
			return []byte(netstatHeader), nil
		}
		return []byte(netstatHeader + netstatRow("127.0.0.1.18970", "127.0.0.1.55233", "ESTABLISHED", "defenseclaw-gate:4242")), nil
	}
	if err := verifyManagedConnectedPeer(context.Background(), client, server, standaloneGatewayLaunchdLabel); err != nil {
		t.Fatalf("a gateway row that appeared late was refused: %v", err)
	}
}
