// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

var userScopedProofCallerSID = func(r *http.Request) (string, error) {
	local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	remote, err := net.ResolveTCPAddr("tcp4", r.RemoteAddr)
	if local == nil || remote == nil || err != nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return "", errors.New("listener proof caller has no loopback TCP connection")
	}
	return hookexec.ConnectedLoopbackClientSID(local, remote)
}

func userScopedProofCallerMatches(r *http.Request, identity string) bool {
	if identity == "" {
		return false
	}
	got, err := userScopedProofCallerSID(r)
	return err == nil && strings.EqualFold(got, identity)
}
