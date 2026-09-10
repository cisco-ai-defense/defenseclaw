// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"

	winpath "github.com/defenseclaw/defenseclaw/internal/winpath"
)

// listenSecuredForOS is the Windows bind. Mode bits and uid/gid do not
// map to DACLs, so the boundary is the ACL applied to the directory
// and the socket, plus two refusals that have to happen before either.
func listenSecuredForOS(ctx context.Context, spec ListenSpec) (net.Listener, error) {
	// An override pointing outside the dedicated directory would have
	// its original DACL REPLACED by the baseline below -- including
	// ACEs an unrelated installer relies on.
	if err := validateWindowsSocketPathOverride(spec.Path); err != nil {
		return nil, err
	}
	dir := dirOf(spec.Path)
	if err := os.MkdirAll(dir, windowsSocketParentDirMode); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	// A local user who pre-creates a junction at the target directory
	// before the daemon starts would otherwise have the baseline ACL
	// rewritten onto the junction's target, which they control. The
	// walk goes to the volume root so an ancestor junction is refused
	// too.
	if err := winpath.RejectReparseChain(dir); err != nil {
		return nil, fmt.Errorf("ipc: reject reparse chain %s: %w", dir, err)
	}
	if err := applyBaselineIPCACL(dir, aclObjectDirectory); err != nil {
		return nil, err
	}
	if err := os.Remove(spec.Path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: remove stale socket %s: %w", spec.Path, err)
	}

	var lc net.ListenConfig
	inner, err := lc.Listen(ctx, "unix", spec.Path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", spec.Path, err)
	}
	if err := applyBaselineIPCACL(spec.Path, aclObjectSocketFile); err != nil {
		_ = inner.Close()
		return nil, err
	}
	return inner, nil
}
