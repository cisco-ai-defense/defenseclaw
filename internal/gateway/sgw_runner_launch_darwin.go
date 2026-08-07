// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sgwDarwinCSValid   uint32 = 0x00000001
	sgwDarwinCSHard    uint32 = 0x00000100
	sgwDarwinCSKill    uint32 = 0x00000200
	sgwDarwinCSRuntime uint32 = 0x00010000
	sgwCodesignLimit          = 16 * 1024
	sgwCodesignTimeout        = 5 * time.Second

	sgwLCLoadDylib       uint32 = 0x0000000c
	sgwLCIDDylib         uint32 = 0x0000000d
	sgwLCLoadDylinker    uint32 = 0x0000000e
	sgwLCIDDylinker      uint32 = 0x0000000f
	sgwLCPreboundDylib   uint32 = 0x00000010
	sgwLCLoadWeakDylib   uint32 = 0x80000018
	sgwLCRPath           uint32 = 0x8000001c
	sgwLCReexportDylib   uint32 = 0x8000001f
	sgwLCLazyLoadDylib   uint32 = 0x00000020
	sgwLCLoadUpwardDylib uint32 = 0x80000023
	sgwLCDyldEnvironment uint32 = 0x00000027
	sgwLCLoadFVMLib      uint32 = 0x00000006
	sgwLCIDFVMLib        uint32 = 0x00000007
)

func startAdmittedSGWRunner(
	receipt *sgwModuleReceipt,
	runnerPath string,
	env []string,
	args []string,
) (*sgwAdmittedCommand, error) {
	if receipt == nil || receipt.runnerLaunch.Mode != "darwin-running-code-v1" {
		return nil, errors.New("s-gw native runner launch admission is unavailable")
	}
	if err := inspectSGWDarwinRunner(runnerPath, receipt); err != nil {
		return nil, err
	}

	cmd := exec.Command(runnerPath, args...)
	cmd.Dir = receipt.PackageRoot
	cmd.Env = append([]string(nil), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("create s-gw credential broker input")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create s-gw credential broker output")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create s-gw credential broker diagnostics")
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, errors.New("start suspended s-gw native runner")
	}
	pid := cmd.Process.Pid
	cleanup := func() {
		_ = cmd.Process.Kill()
		_ = unix.PtraceDetach(pid)
		_ = cmd.Wait()
		_ = stdin.Close()
	}

	var status unix.WaitStatus
	waited, err := unix.Wait4(pid, &status, unix.WUNTRACED, nil)
	if err != nil || waited != pid || !status.Stopped() {
		cleanup()
		return nil, errors.New("suspend s-gw native runner before admission")
	}
	if err := verifySGWDarwinRunningCode(pid, receipt.runnerLaunch); err != nil {
		cleanup()
		return nil, err
	}
	if err := unix.PtraceDetach(pid); err != nil {
		cleanup()
		return nil, errors.New("resume admitted s-gw native runner")
	}
	return &sgwAdmittedCommand{
		process: &sgwExecProcess{cmd: cmd},
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

func inspectSGWDarwinRunner(path string, receipt *sgwModuleReceipt) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open verified s-gw native runner")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("open verified s-gw native runner")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > sgwModuleTotalBytes {
		return errors.New("s-gw native runner is invalid")
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(file, sgwModuleTotalBytes+1))
	if err != nil || read != info.Size() || read > sgwModuleTotalBytes ||
		hex.EncodeToString(digest.Sum(nil)) != receipt.Runner.SHA256 {
		return errors.New("s-gw native runner integrity check failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("inspect s-gw native runner image")
	}
	binary, err := macho.NewFile(file)
	if err != nil {
		return errors.New("s-gw native runner is not a valid Mach-O image")
	}
	defer binary.Close()
	wantCPU := macho.CpuArm64
	if strings.HasSuffix(receipt.Target, "-x64") {
		wantCPU = macho.CpuAmd64
	}
	if binary.Type != macho.TypeExec || binary.Cpu != wantCPU {
		return errors.New("s-gw native runner Mach-O identity is invalid")
	}
	if err := validateSGWDarwinLoadCommands(binary.ByteOrder, binary.Loads); err != nil {
		return err
	}
	return nil
}

func sgwDarwinSystemLibrary(path string) bool {
	if path == "" || strings.ContainsRune(path, '\x00') || pathpkg.Clean(path) != path {
		return false
	}
	return strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/System/Library/")
}

func validateSGWDarwinLoadCommands(order binary.ByteOrder, loads []macho.Load) error {
	if order == nil || len(loads) == 0 {
		return errors.New("s-gw native runner Mach-O load commands are invalid")
	}
	dylinkerCount := 0
	for _, load := range loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return errors.New("s-gw native runner Mach-O load command is invalid")
		}
		command := order.Uint32(raw[:4])
		commandSize := order.Uint32(raw[4:8])
		if commandSize < 8 || commandSize%8 != 0 || uint64(commandSize) != uint64(len(raw)) {
			return errors.New("s-gw native runner Mach-O load command is invalid")
		}
		switch command {
		case sgwLCLoadDylib, sgwLCLoadWeakDylib, sgwLCReexportDylib,
			sgwLCLazyLoadDylib, sgwLCLoadUpwardDylib:
			name, err := sgwDarwinLoadCommandString(order, raw, 24)
			if err != nil || !sgwDarwinSystemLibrary(name) {
				return errors.New("s-gw native runner dependency is not system-owned")
			}
		case sgwLCLoadDylinker:
			name, err := sgwDarwinLoadCommandString(order, raw, 12)
			if err != nil || name != "/usr/lib/dyld" {
				return errors.New("s-gw native runner dynamic linker is invalid")
			}
			dylinkerCount++
		case sgwLCRPath, sgwLCDyldEnvironment:
			return errors.New("s-gw native runner carries an unsafe Mach-O loader command")
		case sgwLCIDDylib, sgwLCIDDylinker, sgwLCPreboundDylib, sgwLCLoadFVMLib, sgwLCIDFVMLib:
			return errors.New("s-gw native runner carries an unsupported Mach-O loader command")
		}
	}
	if dylinkerCount != 1 {
		return errors.New("s-gw native runner dynamic linker is invalid")
	}
	return nil
}

func sgwDarwinLoadCommandString(
	order binary.ByteOrder,
	raw []byte,
	minimumOffset uint32,
) (string, error) {
	if len(raw) < 12 {
		return "", errors.New("Mach-O load command string is invalid")
	}
	offset := order.Uint32(raw[8:12])
	if offset < minimumOffset || offset >= uint32(len(raw)) {
		return "", errors.New("Mach-O load command string is invalid")
	}
	encoded := raw[offset:]
	terminator := -1
	for index, value := range encoded {
		if value == 0 {
			terminator = index
			break
		}
	}
	if terminator <= 0 {
		return "", errors.New("Mach-O load command string is invalid")
	}
	for _, value := range encoded[terminator+1:] {
		if value != 0 {
			return "", errors.New("Mach-O load command string padding is invalid")
		}
	}
	return string(encoded[:terminator]), nil
}

func verifySGWDarwinRunningCode(pid int, admission sgwRunnerLaunchAdmission) error {
	codesign := "/usr/bin/codesign"
	info, err := os.Lstat(codesign)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("trusted macOS code verifier is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("trusted macOS code verifier is unavailable")
	}
	requirement := sgwDarwinCodeRequirement(admission)
	ctx, cancel := context.WithTimeout(context.Background(), sgwCodesignTimeout)
	defer cancel()
	check := exec.CommandContext(
		ctx,
		codesign,
		"--verify",
		"--verbose=1",
		"-R="+requirement,
		strconv.Itoa(pid),
	)
	check.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output := &sgwDarwinBoundedWriter{remaining: sgwCodesignLimit}
	check.Stdout = output
	check.Stderr = output
	if err := check.Run(); err != nil || ctx.Err() != nil || output.exceeded {
		return errors.New("s-gw running code signature is invalid")
	}

	var flags uint32
	_, _, errno := unix.Syscall6(
		unix.SYS_CSOPS,
		uintptr(pid),
		0,
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		0,
		0,
	)
	if errno != 0 {
		return errors.New("inspect s-gw running code flags")
	}
	required := sgwDarwinCSValid | sgwDarwinCSHard | sgwDarwinCSKill | sgwDarwinCSRuntime
	if flags&required != required {
		return errors.New("s-gw running code flags are insufficient")
	}
	return nil
}

func sgwDarwinCodeRequirement(admission sgwRunnerLaunchAdmission) string {
	return fmt.Sprintf(
		`anchor apple generic and identifier "%s" and certificate leaf[subject.OU] = "%s" and cdhash H"%s"`,
		admission.SigningID,
		admission.TeamID,
		admission.CDHash,
	)
}

type sgwDarwinBoundedWriter struct {
	remaining int
	exceeded  bool
}

func (writer *sgwDarwinBoundedWriter) Write(value []byte) (int, error) {
	if len(value) <= writer.remaining {
		writer.remaining -= len(value)
		return len(value), nil
	}
	writer.exceeded = true
	return 0, errors.New("codesign output exceeded limit")
}
