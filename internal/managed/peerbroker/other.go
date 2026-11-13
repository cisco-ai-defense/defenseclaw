// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package peerbroker

import (
	"context"
	"net"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// Client is the gateway end (Windows only).
type Client struct{}

// NewClient is unsupported off Windows.
func NewClient(string) (*Client, error) { return nil, ErrUnsupportedPlatform }

// Lookup is unsupported off Windows.
func (*Client) Lookup(context.Context, *net.TCPAddr, *net.TCPAddr) (peercred.PeerIdentity, error) {
	return peercred.PeerIdentity{}, ErrUnsupportedPlatform
}

// Server is the guardian end (Windows only).
type Server struct{}

// NewServer is unsupported off Windows.
func NewServer(string, func(Event)) (*Server, error) { return nil, ErrUnsupportedPlatform }

// Serve is unsupported off Windows.
func (*Server) Serve(context.Context, chan<- struct{}) error { return ErrUnsupportedPlatform }
