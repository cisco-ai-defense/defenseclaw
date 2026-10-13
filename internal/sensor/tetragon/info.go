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

// Package tetragon reads a customer-run Tetragon agent for the managed Linux
// sensor helper, and only for it.
//
// Tetragon's gRPC API has no authorization: whoever can open its socket can
// load deny or kill policies for every process on the host. A connection is
// therefore root-equivalent, and this package is built around keeping that
// reach as small as the job:
//
//   - It dials only a unix socket named by Tetragon's root-owned info file,
//     and only when the socket and its directory are root-owned, not world
//     writable, and served by uid 0 as the pid the info file names
//     (SO_PEERCRED). A TCP address is never dialled.
//   - Every RPC passes a per-scope allowlist: consume can read events, the
//     version, the agent info and the policy list; policy (observe and
//     enforce) can also add, delete and configure policies; cleanup can only
//     list and delete. Anything else is refused before it is sent.
//   - Events are requested without ancestors, environment variables,
//     capabilities, namespaces or pod data, mapped to plane events in the
//     helper, and every command line is redacted before it leaves.
//
// The per-user gateway never imports this package: only the helper does.
package tetragon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Reason codes start every error this package returns for a session that
// could not be opened. The coverage report and the lifecycle's warnings use
// them as they are.
const (
	// ReasonUnavailable: no info file, no socket, no answer, or the stream
	// ended.
	ReasonUnavailable = "tetragon_unavailable"
	// ReasonTCPAPI: the info file names a TCP address. Never dialled: any
	// local account could load kernel policies through it.
	ReasonTCPAPI = "tetragon_tcp_api"
	// ReasonUntrusted: the info file, the socket, its directory or the peer
	// failed an ownership, mode or SO_PEERCRED check.
	ReasonUntrusted = "tetragon_untrusted_endpoint"
	// ReasonUnsupportedVersion: the agent is outside the supported window.
	ReasonUnsupportedVersion = "tetragon_unsupported_version"
)

// Error is a refusal with its reason code.
type Error struct {
	Code   string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.Err }

func refuse(code string, err error, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...), Err: err}
}

// ReasonCode is the reason code of err, or ReasonUnavailable.
func ReasonCode(err error) string {
	var refusal *Error
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ReasonUnavailable
}

// DefaultInfoPath is where Tetragon writes its discovery file.
const DefaultInfoPath = "/var/run/tetragon/tetragon-info.json"

// infoLimit bounds the discovery file (370 bytes on a stock agent).
const infoLimit = 64 << 10

// Info is Tetragon's discovery file. Only the fields the helper uses are
// decoded.
type Info struct {
	ServerAddress  string `json:"server_address"`
	MetricsAddress string `json:"metrics_address"`
	PID            int    `json:"pid"`
}

// SocketPath is the unix socket the info file names, or "" and false when it
// names anything else (a TCP address).
func (i Info) SocketPath() (string, bool) {
	address := strings.TrimSpace(i.ServerAddress)
	var path string
	switch {
	case strings.HasPrefix(address, "unix://"):
		path = strings.TrimPrefix(address, "unix://")
	case strings.HasPrefix(address, "unix:"):
		path = strings.TrimPrefix(address, "unix:")
	default:
		return "", false
	}
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	return path, true
}

// ReadInfo reads and checks Tetragon's discovery file: root-owned, a regular
// file, not group- or world-writable. The reconciler polls it to notice a
// Tetragon restart (the pid changes), because a restart drops every policy
// loaded over gRPC.
func ReadInfo(path string) (Info, error) {
	return readInfo(path, rootTrust)
}

func readInfo(path string, trust trustPolicy) (Info, error) {
	if path == "" {
		path = DefaultInfoPath
	}
	if err := trust.checkInfoFile(path); err != nil {
		return Info{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return Info{}, refuse(ReasonUnavailable, err, "open %s: %v", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, infoLimit+1))
	if err != nil {
		return Info{}, refuse(ReasonUnavailable, err, "read %s: %v", path, err)
	}
	if len(data) > infoLimit {
		return Info{}, refuse(ReasonUntrusted, nil, "%s is larger than %d bytes", path, infoLimit)
	}
	var info Info
	if err := json.Unmarshal(data, &info); err != nil {
		return Info{}, refuse(ReasonUnavailable, err, "parse %s: %v", path, err)
	}
	if info.PID <= 0 {
		return Info{}, refuse(ReasonUnavailable, nil, "%s names no Tetragon pid", path)
	}
	return info, nil
}
