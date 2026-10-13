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

package sandboxfeed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// handshakeTimeout bounds the request and the header.
const handshakeTimeout = 5 * time.Second

// Conn is one open feed stream.
type Conn struct {
	conn    net.Conn
	scanner *bufio.Scanner
	header  Header
}

// Dial opens the feed at path (DefaultSocketPath when empty): it refuses a
// socket that is not root's, or served by a process that is not root's, asks
// for the stream, and refuses a feed whose protocol this build does not read
// (a *SkewError, errors.Is ErrVersionSkew). A missing socket is
// ErrNotInstalled; one the caller may not open (not in the docker group)
// ErrNotPermitted.
func Dial(ctx context.Context, path string) (*Conn, error) {
	if path == "" {
		path = DefaultSocketPath
	}
	return dial(ctx, path, rootTrust)
}

// trustPolicy is who must own the socket and serve it: root in production,
// the test's own uid in tests.
type trustPolicy struct{ uid int }

var rootTrust = trustPolicy{uid: 0}

func dial(ctx context.Context, path string, trust trustPolicy) (*Conn, error) {
	if err := checkSocket(path, trust); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	raw, err := dialer.DialContext(dialCtx, "unix", path)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
			return nil, fmt.Errorf("%w: %v", ErrNotInstalled, err)
		case errors.Is(err, os.ErrPermission):
			return nil, fmt.Errorf("%w: %v (the feed is for members of the %s group)", ErrNotPermitted, err, DockerGroup)
		}
		return nil, err
	}
	if err := checkServer(raw, trust); err != nil {
		_ = raw.Close()
		return nil, err
	}
	c := &Conn{conn: raw, scanner: NewLineScanner(raw)}
	if err := c.handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) handshake() error {
	_ = c.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := WriteLine(c.conn, Request{Version: ProtocolVersion, Op: OpSandboxExecs}); err != nil {
		return fmt.Errorf("sandboxfeed: send the request: %w", err)
	}
	if err := ReadLine(c.scanner, &c.header); err != nil {
		return fmt.Errorf("sandboxfeed: read the header: %w", err)
	}
	_ = c.conn.SetDeadline(time.Time{})
	if c.header.Error == HeaderErrorVersionSkew || !accepts(c.header.Protocol) {
		return &SkewError{Server: c.header.Protocol, Client: ProtocolVersion, Build: c.header.Build}
	}
	if c.header.Error != "" {
		return fmt.Errorf("sandboxfeed: the feed refused the request: %s", c.header.Error)
	}
	return nil
}

// Header is the feed's answer to the request.
func (c *Conn) Header() Header { return c.header }

// Next blocks for the next frame. A frame of a kind this build does not know
// is skipped.
func (c *Conn) Next() (Frame, error) {
	for {
		var frame Frame
		if err := ReadLine(c.scanner, &frame); err != nil {
			return Frame{}, err
		}
		switch frame.Kind {
		case FrameExec, FrameExit, FrameSummary, FrameStatus:
			return frame, nil
		}
	}
}

// Close ends the stream.
func (c *Conn) Close() error { return c.conn.Close() }
