// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed benign contributor payload. Build this file explicitly on Windows;
// it is not a production runtime or an arbitrary-command launcher.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func event(name string, ok bool, detail any) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"probe": name, "ok": ok, "detail": detail})
}

func denied(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.Errno(10013)) // WSAEACCES
}

func appContainer() (bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()
	var value, size uint32
	// TOKEN_INFORMATION_CLASS.TokenIsAppContainer from winnt.h.
	err := windows.GetTokenInformation(token, 29, (*byte)(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value)), &size)
	return value != 0, err
}

func console() {
	input, inErr := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	output, outErr := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	stderr, errErr := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	var inMode, outMode, errMode uint32
	if inErr == nil {
		inErr = windows.GetConsoleMode(input, &inMode)
	}
	if outErr == nil {
		outErr = windows.GetConsoleMode(output, &outMode)
	}
	if errErr == nil {
		errErr = windows.GetConsoleMode(stderr, &errMode)
	}
	var info windows.ConsoleScreenBufferInfo
	infoErr := windows.GetConsoleScreenBufferInfo(output, &info)
	event("console_handles", inErr == nil && outErr == nil && errErr == nil, []bool{inErr == nil, outErr == nil, errErr == nil})
	event("console", infoErr == nil, map[string]any{
		"columns": info.Window.Right - info.Window.Left + 1, "rows": info.Window.Bottom - info.Window.Top + 1,
	})
}

func main() {
	mode := flag.String("mode", "boundary", "fixed probe: boundary, terminal, console-control, exit23, timeout, tree, leaf")
	root := flag.String("root", "", "task-owned synthetic fixture root")
	tcpPort := flag.Int("tcp-port", 0, "task-owned IPv4 loopback canary listener")
	udpPort := flag.Int("udp-port", 0, "task-owned IPv4 loopback canary receiver")
	tcp6Port := flag.Int("tcp6-port", 0, "task-owned IPv6 loopback canary listener")
	udp6Port := flag.Int("udp6-port", 0, "task-owned IPv6 loopback canary receiver")
	flag.Parse()
	event("started", true, map[string]any{"pid": os.Getpid(), "mode": *mode})
	switch *mode {
	case "exit23":
		os.Exit(23)
	case "timeout":
		time.Sleep(15 * time.Second)
		os.Exit(44)
	case "leaf":
		contained, err := appContainer()
		event("descendant_token", err == nil && contained, os.Getpid())
		time.Sleep(25 * time.Second)
		return
	case "tree":
		executable, err := os.Executable()
		if err != nil {
			event("descendant_start", false, fmt.Sprint(err))
			os.Exit(2)
		}
		child := exec.Command(executable, "-mode", "leaf")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			event("descendant_start", false, fmt.Sprint(err))
			os.Exit(2)
		}
		event("descendant_ready", true, child.Process.Pid)
		_ = child.Wait()
		return
	case "terminal", "console-control":
		contained, tokenErr := appContainer()
		event("terminal_token", tokenErr == nil && contained, "AppContainer required")
		cwd, cwdErr := os.Getwd()
		rel, homeErr := filepath.Rel(*root, os.Getenv("HOME"))
		private := filepath.IsAbs(*root) && cwdErr == nil && homeErr == nil &&
			strings.EqualFold(cwd, filepath.Join(*root, "workspace")) && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
		event("terminal_private_state", private, "private workspace and HOME required")
		if *mode == "terminal" && (tokenErr != nil || !contained || !private) {
			os.Exit(2)
		}
		console()
		interrupts := make(chan os.Signal, 1)
		interruptAck := make(chan struct{}, 1)
		signal.Notify(interrupts, os.Interrupt)
		defer signal.Stop(interrupts)
		go func() {
			for range interrupts {
				event("interrupt", true, "CTRL_C")
				select {
				case interruptAck <- struct{}{}:
				default:
				}
			}
		}()
		for {
			input := bufio.NewScanner(os.Stdin)
			for input.Scan() {
				switch input.Text() {
				case "hello":
					event("input_ack", true, "hello")
				case "dimensions":
					console()
				case "exit7":
					os.Exit(7)
				default:
					event("unexpected_input", false, "only fixed probe commands are accepted")
				}
			}
			// Windows console Ctrl-C can return a zero-length read before
			// os/signal delivers the interrupt. Resume only after an actual
			// interrupt acknowledgement, with a bounded wait; ordinary EOF
			// still closes this fixed probe's input.
			if input.Err() != nil && !errors.Is(input.Err(), syscall.Errno(995)) {
				event("input_closed", false, fmt.Sprint(input.Err()))
				return
			}
			select {
			case <-interruptAck:
				continue
			case <-time.After(500 * time.Millisecond):
				event("input_closed", input.Err() == nil, fmt.Sprint(input.Err()))
				return
			}
		}
	case "boundary":
	default:
		event("mode", false, "unsupported fixed probe")
		os.Exit(2)
	}
	if !filepath.IsAbs(*root) || *tcpPort < 1 || *tcpPort > 65535 || *udpPort < 1 || *udpPort > 65535 || *tcp6Port < 1 || *tcp6Port > 65535 || *udp6Port < 1 || *udp6Port > 65535 {
		event("fixture", false, "an absolute task-owned root and loopback listener ports are required")
		os.Exit(2)
	}
	failed := false
	check := func(name string, ok bool, detail any) {
		event(name, ok, detail)
		failed = failed || !ok
	}
	contained, tokenErr := appContainer()
	check("appcontainer_token", tokenErr == nil && contained, fmt.Sprint(tokenErr))
	cwd, cwdErr := os.Getwd()
	check("cwd", cwdErr == nil && strings.EqualFold(filepath.Clean(cwd), filepath.Join(*root, "workspace")), cwd)
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"} {
		value := os.Getenv(key)
		rel, err := filepath.Rel(*root, value)
		check("private_"+key, err == nil && value != "" && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)), value)
	}
	check("secret_environment_absent", os.Getenv("OPENAI_API_KEY") == "", "synthetic canary key only")
	err := os.WriteFile(filepath.Join(cwd, "allowed-write.txt"), []byte("AXIS_ALLOWED_WRITE"), 0o600)
	check("workspace_write", err == nil, fmt.Sprint(err))
	outside := filepath.Join(*root, "outside-sentinel.txt")
	_, err = os.ReadFile(outside)
	check("outside_read_denied", denied(err), fmt.Sprint(err))
	err = os.WriteFile(outside, []byte("UNEXPECTED_OUTSIDE_WRITE"), 0o600)
	check("outside_write_denied", denied(err), fmt.Sprint(err))
	readonly := filepath.Join(*root, "readonly", "reference.txt")
	value, err := os.ReadFile(readonly)
	check("readonly_read", err == nil && string(value) == "AXIS_READONLY_SENTINEL", fmt.Sprint(err))
	err = os.WriteFile(readonly, []byte("UNEXPECTED_READONLY_WRITE"), 0o600)
	check("readonly_write_denied", denied(err), fmt.Sprint(err))
	tcp, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", *tcpPort), 2*time.Second)
	if tcp != nil {
		_ = tcp.Close()
	}
	check("loopback_tcp_denied", denied(err), fmt.Sprint(err))
	udp, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", *udpPort))
	if err == nil {
		_, err = udp.Write([]byte("AXIS_SYNTHETIC_DATAGRAM"))
		_ = udp.Close()
	}
	// UDP writes may be accepted locally and then filtered asynchronously.
	// Only the host receiver can determine whether this datagram arrived.
	check("loopback_udp_send", err == nil || denied(err), map[string]any{
		"accepted_locally": err == nil, "access_denied": denied(err), "error": fmt.Sprint(err),
	})
	tcp6, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", *tcp6Port), 2*time.Second)
	if tcp6 != nil {
		_ = tcp6.Close()
	}
	check("loopback_tcp6_denied", denied(err), fmt.Sprint(err))
	udp6, err := net.Dial("udp6", fmt.Sprintf("[::1]:%d", *udp6Port))
	if err == nil {
		_, err = udp6.Write([]byte("AXIS_SYNTHETIC_DATAGRAM_IPV6"))
		_ = udp6.Close()
	}
	check("loopback_udp6_send", err == nil || denied(err), map[string]any{
		"accepted_locally": err == nil, "access_denied": denied(err), "error": fmt.Sprint(err),
	})
	if failed {
		os.Exit(1)
	}
}
