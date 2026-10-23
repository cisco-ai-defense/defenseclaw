// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentprocess

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsLaunchEnvironmentReadsAnotherProcess(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestWindowsLaunchEnvironmentHelper$")
	command.Env = append(os.Environ(), "DC_LAUNCH_ENV_HELPER=1", "OPENCODE_PURE=1", "HERMES_SAFE_MODE=1", "DC_PRIVATE_MARKER=do-not-retain")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child did not start: %q, %v", line, err)
	}
	env, err := LaunchEnvironmentForPID(command.Process.Pid)
	if err != nil || env["OPENCODE_PURE"] != "1" || env["HERMES_SAFE_MODE"] != "1" || env["USERPROFILE"] == "" || env["PROGRAMDATA"] == "" {
		t.Fatalf("selected child launch environment unavailable: %v, %v", env, err)
	}
	if _, kept := env["DC_PRIVATE_MARKER"]; kept {
		t.Fatal("unselected environment value was retained")
	}
	_ = stdin.Close()
}

func TestWindowsLaunchEnvironmentHelper(t *testing.T) {
	if os.Getenv("DC_LAUNCH_ENV_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func TestWindowsLaunchEnvironmentRejectsIncompleteAndConflictingBlocks(t *testing.T) {
	encode := func(text string) []byte {
		units := utf16.Encode([]rune(text))
		raw := make([]byte, 2*len(units))
		for i, unit := range units {
			binary.LittleEndian.PutUint16(raw[2*i:], unit)
		}
		return raw
	}
	for _, raw := range [][]byte{
		encode("OPENCODE_PURE=1\x00"),
		encode("OPENCODE_PURE=1\x00opencode_pure=0\x00\x00"),
		encode("OPENCODE_PURE=1\x00\x00trailing"),
	} {
		if _, err := parseLaunchEnvironmentBlock(raw); err == nil {
			t.Fatalf("malformed block was accepted: %q", raw)
		}
	}
	parsed, err := parseLaunchEnvironmentBlock(encode("=C:=C:\\Users\\alice\x00UserProfile=C:\\Users\\alice\x00ProgramData=C:\\ProgramData\x00OPENCODE_CONFIG_DIR=C:\\extra\x00DC_PRIVATE_MARKER=secret\x00\x00"))
	if err != nil || !strings.EqualFold(parsed["USERPROFILE"], `C:\Users\alice`) || parsed["PROGRAMDATA"] != `C:\ProgramData` || len(parsed) != 2 {
		t.Fatalf("selected keys = %v, %v", parsed, err)
	}
	var pointer [8]byte
	binary.LittleEndian.PutUint64(pointer[:], 0x1234567812345678)
	if launchPointer(pointer[:], 4) != 0x12345678 || launchPointer(pointer[:], 8) != 0x1234567812345678 {
		t.Fatal("native and WOW64 process pointers were decoded incorrectly")
	}
}
