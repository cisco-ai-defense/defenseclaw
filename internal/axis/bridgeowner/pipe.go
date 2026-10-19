// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeowner

import "os"

type Direction uint8

const (
	ToPeer Direction = iota + 1
	FromPeer
)

// PrivatePipe holds newly created, unconnected-to-any-workload stdio ends.
// Parent is deadline-capable. Child is suitable for explicit stdio inheritance
// by a native launcher; it must close its parent copy after suspended creation.
// No end is globally marked inheritable. The caller owns both ends on success.
type PrivatePipe struct{ Parent, Child *os.File }

// NewPrivatePipe creates one private local channel, never a daemon/listener or
// discoverable service. Windows uses a random single-instance owner-only pipe
// name because anonymous Windows pipes cannot meet the parent's deadline
// contract. The client end is connected and its creator verified before return.
func NewPrivatePipe(direction Direction) (PrivatePipe, error) {
	if direction != ToPeer && direction != FromPeer {
		return PrivatePipe{}, ErrClosed
	}
	return newPrivatePipe(direction)
}
