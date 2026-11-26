// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bytes"
	"context"
	"syscall"
)

// GitOpForTest runs a GitCommand request as a separated relay whose agent
// is uid:gid, with its review copies in parents and wrap put before every
// script it runs as its own user (GAP-0795 root tests).
func GitOpForTest(ctx context.Context, argv []string, dir string, env map[string]string, uid, gid uint32, parents []string, wrap string) (string, string, int) {
	gitScratchParents, gitTestWrap = parents, wrap
	sp := &separation{cred: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}}}
	var out, errb bytes.Buffer
	code := runGitOp(ctx, argv, dir, env, sp, &out, &errb)
	return out.String(), errb.String(), code
}
