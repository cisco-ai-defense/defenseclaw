// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	selinuxpolicy "github.com/defenseclaw/defenseclaw/packaging/selinux"
	"golang.org/x/sys/unix"
)

// SELinux-confined users (user_u, staff_u, ...) could not reach the hook
// socket: user_t may not even stat a var_run_t socket, and the denial is
// hidden by a dontaudit rule, so every hook they ran was refused with
// enterprise_managed_gateway_peer_unverified while status and verify were
// green (GAP-0772). On a host with SELinux enabled the lifecycle loads the
// DefenseClaw policy module (packaging/selinux), which labels the socket and
// lets user domains connect; status and verify report a host without it.
//
// The module used to let user domains connect to every unconfined_service_t
// socket, any unconfined service's included (GAP-1143). It now labels the
// gateway binary, systemd starts the gateway in its own domain and gives the
// listening sockets that domain's label, and user domains may connect only
// to it.
const (
	// codeSELinuxModule warns that the module could not be loaded or removed.
	codeSELinuxModule = "selinux_module"
	// codeSELinuxModuleMissing warns that SELinux-confined users cannot reach
	// the hook socket.
	codeSELinuxModuleMissing = "selinux_module_missing"
	// selinuxModuleStamp records the digest of the module the lifecycle
	// loaded, so a transaction reloads it only when it changed.
	selinuxModuleStamp = "selinux-module.sha256"
)

// selinuxEnabled reports whether the kernel runs SELinux (enforcing or
// permissive).
func (e *Env) selinuxEnabled() bool {
	return e.GOOS == "linux" && exists(e.P("/sys/fs/selinux/enforce"))
}

// selinuxModuleLoaded reports whether the policy store holds the module, at
// any priority and for any policy type.
func (e *Env) selinuxModuleLoaded() bool {
	matches, _ := filepath.Glob(e.P(filepath.Join("/var/lib/selinux/*/active/modules/*", selinuxpolicy.ModuleName)))
	return len(matches) > 0
}

// selinuxModuleStale reports an SELinux host whose policy store does not
// hold the module this release ships, so the next transaction loads it.
func (e *Env) selinuxModuleStale() bool {
	if !e.selinuxEnabled() {
		return false
	}
	stamp := filepath.Join(e.P(e.Layout.LifecycleDir), selinuxModuleStamp)
	recorded, err := readBounded(stamp, 128)
	return err != nil || strings.TrimSpace(string(recorded)) != sha256Bytes(selinuxpolicy.Module()) || !e.selinuxModuleLoaded()
}

// ensureSELinuxModule loads the DefenseClaw module when SELinux is enabled
// and the store does not hold the copy this release ships. It reports
// whether it loaded it. A failure is a warning: only confined users depend
// on it, and their hooks fail closed.
func (l *lifecycle) ensureSELinuxModule(ctx context.Context) bool {
	env := l.env
	if !env.selinuxModuleStale() {
		return false
	}
	module := selinuxpolicy.Module()
	digest := sha256Bytes(module)
	stamp := filepath.Join(env.P(env.Layout.LifecycleDir), selinuxModuleStamp)
	source := filepath.Join(env.P(env.Layout.LifecycleDir), selinuxpolicy.ModuleName+".cil")
	err := env.writeFileAtomic(source, module, 0o600, rootOwner())
	if err == nil {
		_, err = env.Runner.Run(ctx, "semodule", "-i", source)
	}
	_ = removeFile(source)
	if err != nil {
		if !errors.Is(err, ErrCommandNotFound) {
			l.result.AddWarning(codeSELinuxModule, "load the DefenseClaw SELinux module, which SELinux-confined users need to reach the hook socket: "+err.Error())
		}
		return false
	}
	if err := env.writeFileAtomic(stamp, []byte(digest+"\n"), 0o600, rootOwner()); err != nil {
		l.result.AddWarning(codeSELinuxModule, "record the loaded DefenseClaw SELinux module: "+err.Error())
	}
	l.noteChange("loaded the DefenseClaw SELinux module for SELinux-confined users")
	return true
}

// removeSELinuxModule removes the module on uninstall.
func (l *lifecycle) removeSELinuxModule(ctx context.Context) {
	env := l.env
	_ = removeFile(filepath.Join(env.P(env.Layout.LifecycleDir), selinuxModuleStamp))
	if env.GOOS != "linux" || !env.selinuxModuleLoaded() {
		return
	}
	if _, err := env.Runner.Run(ctx, "semodule", "-r", selinuxpolicy.ModuleName); err != nil && !errors.Is(err, ErrCommandNotFound) {
		l.result.AddWarning(codeSELinuxModule, "remove the DefenseClaw SELinux module: "+err.Error()+"; remove it with `semodule -r "+selinuxpolicy.ModuleName+"`")
		return
	}
	// Binaries a package still holds go back to the label of their folder:
	// the gateway's type left with the module.
	if exists(env.P(env.Layout.InstallRoot)) {
		_, _ = env.Runner.Run(ctx, "restorecon", "-R", env.P(env.Layout.InstallRoot))
	}
}

// warnSELinuxConfinedUsers tells status and verify when SELinux-confined
// users cannot reach the hook socket: the module is not loaded, or the
// socket does not carry its label.
func (l *lifecycle) warnSELinuxConfinedUsers() {
	env := l.env
	if !env.selinuxEnabled() {
		return
	}
	repair := "`" + env.lifecycleCommand(ActionRepair) + "`"
	if !env.selinuxModuleLoaded() {
		l.result.AddWarning(codeSELinuxModuleMissing, "SELinux is enabled but the DefenseClaw SELinux module is not loaded, so SELinux-confined users (user_u, staff_u and other confined logins) cannot reach the hook socket and DefenseClaw refuses every hook they run; "+repair+" loads it")
		return
	}
	for _, want := range []struct{ path, kind, label string }{
		{env.Layout.HookSocketPath, "the hook socket", selinuxpolicy.HookSocketType},
		// A gateway started from a binary without its type runs as
		// unconfined_service_t, and so do its listening sockets.
		{filepath.Join(env.Layout.BinDir, binGateway), "the gateway binary", selinuxpolicy.GatewayExecType},
	} {
		buf := make([]byte, 256)
		n, err := unix.Lgetxattr(env.P(want.path), "security.selinux", buf)
		if err != nil || n <= 0 {
			continue
		}
		label := strings.TrimRight(string(buf[:n]), "\x00")
		if !strings.Contains(label, ":"+want.label+":") {
			l.result.AddWarning(codeSELinuxModuleMissing, want.kind+" "+want.path+" is labelled "+label+", not "+want.label+
				", so SELinux-confined users cannot reach the hook socket; "+repair+" relabels it")
		}
	}
}
