// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const subreaperArg = "__defenseclaw_scan_subreaper__"

type subreaperCommand struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// The helper is the scanner's parent and a Linux child subreaper. An MCP
// launcher can create its own process group; when the gateway is SIGKILLed,
// the helper remains alive, adopts the scanner's orphaned descendants and
// ends them before exiting. The command is received over a private pipe,
// never copied into the helper's process arguments.
func init() {
	if len(os.Args) == 2 && os.Args[1] == subreaperArg {
		os.Exit(runSubreaperHelper())
	}
}

// RunTreeIsolated runs a scanner with a child subreaper. Unlike a process
// group, the subreaper also contains launchers and servers that call setsid
// or setpgid. It is used for Linux MCP scans; other platforms use RunTree.
func RunTreeIsolated(ctx context.Context, cmd *exec.Cmd) error {
	if cmd == nil || cmd.Path == "" {
		return exec.ErrNotFound
	}
	if cmd.Err != nil {
		return cmd.Err
	}
	path, err := commandPathFromDir(cmd.Path, cmd.Dir)
	if err != nil {
		return err
	}
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer controlRead.Close()
	defer controlWrite.Close()
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer requestRead.Close()
	defer requestWrite.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if cmd.ProcessState != nil {
		return errors.New("scanner command already ran")
	}
	wrapper := exec.CommandContext(ctx, exe, subreaperArg)
	wrapper.Dir, wrapper.Env = cmd.Dir, cmd.Env
	wrapper.Stdin, wrapper.Stdout, wrapper.Stderr = cmd.Stdin, cmd.Stdout, cmd.Stderr
	wrapper.ExtraFiles = []*os.File{controlRead, requestRead}
	wrapper.WaitDelay = 10 * time.Second
	wrapper.Cancel = func() error { return controlWrite.Close() }
	if err := wrapper.Start(); err != nil {
		return err
	}
	_ = controlRead.Close()
	_ = requestRead.Close()
	args := append([]string(nil), cmd.Args...)
	if len(args) > 0 {
		args = args[1:]
	}
	writeErr := json.NewEncoder(requestWrite).Encode(subreaperCommand{Path: path, Args: args})
	_ = requestWrite.Close()
	if writeErr != nil {
		_ = controlWrite.Close()
		_ = wrapper.Wait()
		return writeErr
	}
	err = wrapper.Wait()
	_ = controlWrite.Close()
	return err
}

// commandPathFromDir is the file exec starts for path: a relative path is
// relative to dir, and a relative or empty dir to this process's folder.
// The helper takes only an absolute path, so a relative scanner command
// (scanners.mcp_scanner.binary: ./bin/...) is resolved here. The parts are
// joined, not cleaned, so ".." after a symlinked folder still names the
// file the kernel opens from that folder.
func commandPathFromDir(path, dir string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	if !filepath.IsAbs(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("scanner: resolve %q: %w", path, err)
		}
		if dir != "" {
			wd += "/" + dir
		}
		dir = wd
	}
	return dir + "/" + path, nil
}

func runSubreaperHelper() int {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "scanner: cannot contain MCP server descendants:", err)
		return 1
	}
	control := os.NewFile(3, "gateway-lifeline")
	request := os.NewFile(4, "scanner-request")
	if control == nil || request == nil {
		return 1
	}
	defer control.Close()
	defer request.Close()
	var spec subreaperCommand
	if err := json.NewDecoder(io.LimitReader(request, 1<<20)).Decode(&spec); err != nil || spec.Path == "" || !filepath.IsAbs(spec.Path) {
		fmt.Fprintln(os.Stderr, "scanner: invalid contained command")
		return 1
	}
	child := exec.Command(spec.Path, spec.Args...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "scanner: start contained command:", err)
		return 1
	}
	done := make(chan struct{})
	go func() {
		var b [1]byte
		_, _ = control.Read(b[:])
		select {
		case <-done:
			return
		default:
		}
		_ = killAdoptedChildren()
		os.Exit(137)
	}()
	err := child.Wait()
	cleanupErr := killAdoptedChildren()
	close(done)
	if cleanupErr != nil {
		fmt.Fprintln(os.Stderr, "scanner: cannot confirm MCP server cleanup:", cleanupErr)
		return 1
	}
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return exited.ExitCode()
	}
	return 1
}

// Killing a direct child makes Linux reparent its children, including a
// launcher in another process group, to this subreaper. Repeat until every
// generation is gone. Children are listed per thread, and Go may launch a
// subprocess from any thread. Every task's children belong only to this
// helper, so no unrelated process is selected by name or process group.
func killAdoptedChildren() error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return err
		}
		children := map[int]bool{}
		for _, task := range tasks {
			raw, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
			if errors.Is(err, os.ErrNotExist) {
				continue // the thread exited during this pass
			}
			if err != nil {
				return err
			}
			for _, field := range strings.Fields(string(raw)) {
				pid, err := strconv.Atoi(field)
				if err == nil && pid > 0 {
					children[pid] = true
				}
			}
		}
		if len(children) == 0 {
			return nil
		}
		for pid := range children {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		for {
			var status syscall.WaitStatus
			pid, _ := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if pid <= 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			return errors.New("MCP server descendants did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
