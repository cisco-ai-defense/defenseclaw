//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
)

var inherited struct {
	once      sync.Once
	err       error
	listeners map[string]*sharedListener
}

// loadInherited adopts the passed descriptors exactly once per process. The
// activation variables are removed from the environment afterwards so
// helper processes the gateway starts cannot adopt the same sockets.
func loadInherited() {
	inherited.once.Do(func() {
		inherited.listeners = map[string]*sharedListener{}
		fds, err := parseListenEnv(os.Getpid(), os.Getenv)
		for _, key := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
			_ = os.Unsetenv(key)
		}
		if err != nil {
			if !errors.Is(err, ErrNotActivated) {
				inherited.err = err
			}
			return
		}
		for _, passed := range fds {
			syscall.CloseOnExec(passed.fd)
			file := os.NewFile(uintptr(passed.fd), "systemd:"+passed.name)
			listener, listenErr := net.FileListener(file)
			// FileListener dups the descriptor; the original is no longer needed.
			_ = file.Close()
			if listenErr != nil {
				inherited.err = fmt.Errorf("systemd: adopt descriptor %q: %w", passed.name, listenErr)
				return
			}
			inherited.listeners[passed.name] = newSharedListener(listener)
		}
	})
}

// Listener returns a view of the socket-activated listener named name
// (FileDescriptorName= in the socket unit). ok is false when the process was
// not activated or systemd passed no descriptor with that name. The view may
// be closed and requested again: the inherited socket stays open for the
// process lifetime.
func Listener(name string) (net.Listener, bool, error) {
	loadInherited()
	if inherited.err != nil {
		return nil, false, inherited.err
	}
	shared, ok := inherited.listeners[name]
	if !ok {
		return nil, false, nil
	}
	return shared.view(), true, nil
}
