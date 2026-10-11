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

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// Hook for tests; production uses the kernel.
var standalonePeerCredentials = peercred.FromConn

// managedStandaloneHTTPClient is the unix standalone-profile transport. The
// hook reaches the gateway only through its peer-authorized unix hook
// socket, and trusts it only after the kernel says who is listening: the
// listener's SO_PEERCRED / LOCAL_PEERCRED uid must be root (a socket held by
// systemd or launchd) or the gateway service account from the root-owned
// runtime descriptor.
//
// There is no loopback TCP fallback. Another local user can hold the TCP
// port while the gateway restarts, and the TCP route authenticates a bearer
// rather than the caller's uid, so a descriptor without a hook socket fails
// closed here instead of selecting TCP.
//
// No request byte is written before the peer check passes, so a local user
// who wins the listener during a gateway restart receives nothing.
func managedStandaloneHTTPClient(
	timeout time.Duration,
	socketPath string,
	serviceUID int,
) (*http.Client, error) {
	if serviceUID < 0 {
		return nil, standalonePeerError("standalone gateway service uid is not configured")
	}
	if strings.TrimSpace(socketPath) == "" {
		return nil, standalonePeerError("standalone hook socket is not configured")
	}
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	if err := validateStandaloneHookSocketPath(socketPath, serviceUID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No socket: the gateway service and its socket unit are stopped.
			return nil, standaloneGatewayStoppedError(err)
		}
		if errors.Is(err, os.ErrPermission) && selinuxActive() {
			return nil, standaloneSELinuxDeniedError(err)
		}
		return nil, standalonePeerError("%v", err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, "unix", socketPath)
				if err != nil {
					if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
						return nil, standaloneGatewayStoppedError(err)
					}
					if errors.Is(err, syscall.EACCES) && selinuxActive() {
						return nil, standaloneSELinuxDeniedError(err)
					}
					return nil, err
				}
				credentials, err := standalonePeerCredentials(conn)
				if err != nil {
					_ = conn.Close()
					return nil, standalonePeerError("read hook socket peer credentials: %v", err)
				}
				if !standaloneTrustedGatewayUID(credentials.UID, serviceUID) {
					_ = conn.Close()
					return nil, standalonePeerError(
						"hook socket listener uid %d is neither root nor the gateway service uid %d",
						credentials.UID, serviceUID)
				}
				return conn, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func standaloneTrustedGatewayUID(uid, serviceUID int) bool {
	return uid == 0 || (serviceUID > 0 && uid == serviceUID)
}

// validateStandaloneHookSocketPath checks the socket before dialing. The
// kernel peer check after connect is the authority; this rejects paths an
// attacker could have arranged and gives a precise diagnostic. The socket's
// directory (after resolving platform symlinks such as macOS /var) must be
// owned by root or the gateway account and writable by no one else.
func validateStandaloneHookSocketPath(path string, serviceUID int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("hook socket path %q is not absolute and clean", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("hook socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("hook socket %s is not a socket", path)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("hook socket directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("hook socket directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("hook socket directory %s must be a directory writable only by its owner", dir)
	}
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || !standaloneTrustedGatewayUID(int(stat.Uid), serviceUID) {
		return fmt.Errorf("hook socket directory %s is not owned by root or the gateway service account", dir)
	}
	return nil
}

// standaloneGatewayStoppedError is a hook socket that is missing or that
// nothing accepts on: the gateway is not running. It stays a peer failure, so
// the hook fails closed in every fail mode, and carries
// errManagedGatewayNotRunning, so the user is told the service is stopped
// instead of being sent to socket ownership checks (GAP-0581).
func standaloneGatewayStoppedError(err error) error {
	return fmt.Errorf("%w: %w: %v", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning, err)
}

// selinuxActive reports whether the kernel runs SELinux.
func selinuxActive() bool {
	_, err := os.Stat("/sys/fs/selinux/enforce")
	return err == nil
}

// standaloneSELinuxDeniedError is a hook socket the account may not stat or
// connect to while SELinux is on: the account is SELinux-confined (user_u,
// staff_u) and the DefenseClaw SELinux module is not loaded. Every user may
// reach the socket otherwise (mode 0666 in a 0755 directory), so the user is
// told the cause instead of "the gateway is not available" (GAP-0772). The
// hook still fails closed.
func standaloneSELinuxDeniedError(err error) error {
	return fmt.Errorf("%w: %w: %v", errManagedGatewayPeerUnverified, errManagedHookSocketSELinuxDenied, err)
}

func standalonePeerError(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errManagedGatewayPeerUnverified, fmt.Sprintf(format, args...))
}
