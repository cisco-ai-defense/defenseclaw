// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package daemon

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestPerUserListenerClassifiesRootOnlyWithBoundIdentity(t *testing.T) {
	if os.Geteuid() == 0 || processSignalable(1) {
		t.Skip("needs a root process visible to a non-root caller")
	}
	uid, err := gatewayProcessUID(1)
	if err != nil || uid != 0 {
		t.Skipf("PID 1 owner is unavailable or not root: uid=%d err=%v", uid, err)
	}
	executable := pid1RecordedExecutable(t)
	identity, err := processStartIdentity(1)
	if err != nil || identity == "" {
		t.Skipf("PID 1 start identity unavailable: %v", err)
	}
	home := t.TempDir()
	d := New(home)
	write := func(info pidInfo) {
		t.Helper()
		raw, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(d.pidFile, raw); err != nil {
			t.Fatal(err)
		}
	}
	strong := pidInfo{PID: 1, Executable: executable, DataDir: home, StartIdentity: identity}
	write(strong)
	known := PortHolder{PID: 1, UID: 0}
	class := func(holder PortHolder, err error, answers bool) PerUserListenerClass {
		return ClassifyPerUserListener("127.0.0.1", 18970, home, holder, err, answers)
	}
	if got := class(known, nil, true); got != PerUserListenerOwnGatewayRunAsRoot {
		t.Fatalf("strong root listener = %v, want own gateway running as root", got)
	}
	if got := class(PortHolder{PID: 2, UID: 0}, nil, true); got != PerUserListenerForeign {
		t.Fatalf("different listener PID = %v, want foreign", got)
	}
	for name, record := range map[string]pidInfo{
		"missing start identity":   {PID: 1, Executable: executable, DataDir: home},
		"changed start identity":   {PID: 1, Executable: executable, DataDir: home, StartIdentity: "different"},
		"missing data directory":   {PID: 1, Executable: executable, StartIdentity: identity},
		"different data directory": {PID: 1, Executable: executable, DataDir: t.TempDir(), StartIdentity: identity},
		"missing executable":       {PID: 1, DataDir: home, StartIdentity: identity},
	} {
		write(record)
		if got := class(known, nil, true); got != PerUserListenerForeign {
			t.Errorf("%s = %v, want foreign", name, got)
		}
	}
	write(strong)
	unlisted := PortHolder{UID: -1}
	if got := class(unlisted, ErrNoListener, false); got != PerUserListenerUnknown {
		t.Errorf("silent unlisted port = %v, want unknown", got)
	}
	if got := class(unlisted, ErrNoListener, true); got != PerUserListenerOwnGatewayRunAsRoot {
		t.Errorf("answering unlisted port with bound root record = %v", got)
	}
	if got := class(PortHolder{UID: 0}, nil, true); got != PerUserListenerOwnGatewayRunAsRoot {
		t.Errorf("root-owned port without visible PID = %v", got)
	}
	if got := class(PortHolder{UID: os.Getuid() + 1}, nil, true); got != PerUserListenerForeign {
		t.Errorf("another non-root account = %v, want foreign", got)
	}
}

func TestPerUserListenerOwnAccountAndUnknown(t *testing.T) {
	home := t.TempDir()
	d := New(home)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := processStartIdentity(os.Getpid())
	if err != nil || identity == "" {
		t.Skipf("current process start identity unavailable: %v", err)
	}
	record := pidInfo{PID: os.Getpid(), Executable: executable, DataDir: home, StartIdentity: identity}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(d.pidFile, raw); err != nil {
		t.Fatal(err)
	}
	own := PortHolder{PID: os.Getpid(), UID: os.Getuid()}
	if got := ClassifyPerUserListener("127.0.0.1", 18970, home, own, nil, true); got != PerUserListenerOwnGateway {
		t.Fatalf("own gateway = %v, want own", got)
	}
	if got := ClassifyPerUserListener("127.0.0.1", 18970, home, PortHolder{UID: -1}, ErrNoListener, false); got != PerUserListenerUnknown {
		t.Fatalf("no listener = %v, want unknown", got)
	}
	if got := ClassifyPerUserListener("127.0.0.1", 18970, home, PortHolder{UID: -1}, ErrNoListener, true); got != PerUserListenerUnlistedOwnProcess {
		t.Fatalf("unlisted own process = %v, want connected-peer verification", got)
	}
	if err := os.Remove(d.pidFile); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyPerUserListener("127.0.0.1", 18970, home, PortHolder{UID: -1}, ErrNoListener, true); got != PerUserListenerForeign {
		t.Fatalf("unlisted port without a strong record = %v, want foreign", got)
	}
	record.DataDir = ""
	raw, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(d.pidFile, raw); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyPerUserListener("127.0.0.1", 18970, home, PortHolder{UID: -1}, ErrNoListener, true); got != PerUserListenerUnlistedOwnProcess {
		t.Fatalf("unlisted account process with an older record = %v, want connected-peer verification", got)
	}
}

func TestRootGatewayStopCommandTargetsQuotedDataHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account's home; $marker")
	binDir := filepath.Join(t.TempDir(), "local bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	command := rootGatewayStopCommand(home)
	if !strings.HasPrefix(command, "sudo env DEFENSECLAW_HOME=") || !strings.HasSuffix(command, " '"+binary+"' stop") {
		t.Fatalf("root stop command = %q", command)
	}
	value := strings.TrimSuffix(strings.TrimPrefix(command, "sudo env DEFENSECLAW_HOME="), " '"+binary+"' stop")
	output, err := exec.Command("/bin/sh", "-c", "printf '%s' "+value).Output()
	if err != nil || string(output) != home {
		t.Fatalf("quoted data home = %q, err = %v, want %q", output, err, home)
	}
}
