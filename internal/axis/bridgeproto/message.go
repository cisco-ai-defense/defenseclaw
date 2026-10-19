// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package bridgeproto defines the private owner-to-host-helper protocol.
// It grants no policy authority and starts no process, listener or goroutine.
package bridgeproto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Version       = 1
	MaxFrameBytes = 256 << 10
	MaxDataBytes  = 16 << 10
)

var ErrProtocol = errors.New("invalid private sandbox bridge protocol")

// Binding correlates a single private helper with the owner's complete local
// records. Digests cannot reconstruct or authorize policy. The owner must pin
// the helper independently, resolve policy locally and use its LaunchGate.
// SessionDigest covers the complete host-owned session identity, not just name.
type Binding struct {
	SessionID       string `json:"session_id"`
	SessionDigest   string `json:"session_digest"`
	PolicyDigest    string `json:"policy_digest"`
	RuntimeDigest   string `json:"runtime_digest"`
	HarnessDigest   string `json:"harness_digest"`
	PreparationHash string `json:"preparation_hash"`
}

type Kind string

const (
	Prepare   Kind = "prepare"
	Launch    Kind = "launch"
	Input     Kind = "input"
	InputEOF  Kind = "input_eof"
	Resize    Kind = "resize"
	Cancel    Kind = "cancel"
	Wait      Kind = "wait"
	Destroy   Kind = "destroy"
	Prepared  Kind = "prepared"
	Started   Kind = "started"
	Output    Kind = "output"
	Exited    Kind = "exited"
	Destroyed Kind = "destroyed"
	Failed    Kind = "failed"
)

// Frame has exactly one typed payload where its kind requires one. Sequence
// is monotonic per direction; Request correlates replies with a host command.
// The session state machine, rather than JSON alone, must admit transitions.
type Frame struct {
	Version  uint16       `json:"version"`
	Sequence uint64       `json:"sequence"`
	Request  uint64       `json:"request"`
	Binding  Binding      `json:"binding"`
	Kind     Kind         `json:"kind"`
	Plan     *Preparation `json:"plan,omitempty"`
	Data     *Data        `json:"data,omitempty"`
	Size     *Size        `json:"size,omitempty"`
	Result   *Result      `json:"result,omitempty"`
	Failure  *Failure     `json:"failure,omitempty"`
}

// Preparation is host-helper input only, never a child launch plan. It omits
// the resolver snapshot, policy provenance, evaluator facts and credentials.
// Paths are admitted artifacts/guest paths selected by the trusted adapter;
// syntax checks here do not verify filesystem custody or policy translation.
// V1 admits only explicit offline execution until a host broker is qualified.
type Preparation struct {
	Backend     string     `json:"backend"`
	Argv        []string   `json:"argv"`
	Environment []Variable `json:"environment"`
	Workdir     string     `json:"workdir"`
	Filesystem  Filesystem `json:"filesystem"`
	Offline     bool       `json:"offline"`
	Terminal    *Size      `json:"terminal,omitempty"`
	TimeoutMS   uint32     `json:"timeout_ms"`
	OutputLimit uint32     `json:"output_limit"`
}

type Variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Filesystem struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
	Deny  []string `json:"deny"`
}

type Size struct {
	Rows    uint16 `json:"rows"`
	Columns uint16 `json:"columns"`
}

// Data is bounded binary stdio. Stream is stdin for Input and stdout/stderr
// for Output; a terminal uses stdout for its merged stream.
type Data struct {
	Stream string `json:"stream"`
	Bytes  []byte `json:"bytes"`
}

type Result struct {
	ExitCode  int32 `json:"exit_code"`
	TimedOut  bool  `json:"timed_out"`
	Truncated bool  `json:"truncated"`
}

// Failure carries a closed reason code, never arbitrary backend diagnostics,
// environment values, paths, stdout or credential material.
type Failure struct {
	Code string `json:"code"`
}

var (
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sessionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	envPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

func text(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func (b Binding) Validate() error {
	if !sessionPattern.MatchString(b.SessionID) {
		return ErrProtocol
	}
	for _, value := range []string{b.SessionDigest, b.PolicyDigest, b.RuntimeDigest, b.HarnessDigest, b.PreparationHash} {
		if !digestPattern.MatchString(value) {
			return ErrProtocol
		}
	}
	return nil
}

func (s Size) valid() bool { return s.Rows > 0 && s.Columns > 0 && s.Rows <= 4096 && s.Columns <= 4096 }

func (p Preparation) Validate() error {
	if (p.Backend != "bubblewrap" && p.Backend != "seatbelt" && p.Backend != "windows_psec") ||
		!p.Offline || len(p.Argv) == 0 || len(p.Argv) > 4096 || !wirePath(p.Backend, p.Argv[0]) ||
		!wirePath(p.Backend, p.Workdir) || p.TimeoutMS == 0 || p.TimeoutMS > 24*60*60*1000 ||
		p.OutputLimit == 0 || p.OutputLimit > 64<<20 || p.Terminal != nil && !p.Terminal.valid() ||
		p.Environment == nil || len(p.Environment) > 256 || p.Filesystem.Read == nil || p.Filesystem.Write == nil || p.Filesystem.Deny == nil {
		return ErrProtocol
	}
	bytes := 0
	for _, arg := range p.Argv {
		if !text(arg, 128<<10) {
			return ErrProtocol
		}
		bytes += len(arg) + 1
	}
	if bytes > 128<<10 {
		return ErrProtocol
	}
	seen := map[string]bool{}
	bytes = 0
	for _, variable := range p.Environment {
		key := variable.Name
		if p.Backend == "windows_psec" {
			key = strings.ToUpper(key)
		}
		if !envPattern.MatchString(variable.Name) || seen[key] || !text(variable.Value, 32<<10) {
			return ErrProtocol
		}
		seen[key] = true
		bytes += len(variable.Name) + len(variable.Value) + 2
	}
	if bytes > 64<<10 {
		return ErrProtocol
	}
	bytes = 0
	for _, paths := range [][]string{p.Filesystem.Read, p.Filesystem.Write, p.Filesystem.Deny} {
		if len(paths) > 256 {
			return ErrProtocol
		}
		seen := map[string]bool{}
		for _, path := range paths {
			if !wirePath(p.Backend, path) || seen[path] {
				return ErrProtocol
			}
			seen[path] = true
			bytes += len(path) + 1
		}
	}
	if bytes > 64<<10 {
		return ErrProtocol
	}
	return nil
}

// wirePath is lexical admission only. Native adapters must retain their own
// verified handles, reject redirects/reparse points and enforce exact grants.
func wirePath(backend, value string) bool {
	if !text(value, 32767) || value == "" {
		return false
	}
	if backend == "windows_psec" {
		return len(value) >= 3 && (value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') && value[1] == ':' && value[2] == '\\'
	}
	return value[0] == '/'
}

func PreparationDigest(p Preparation) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	// Fixed binary encoding avoids differences between Go and Rust JSON
	// escaping, field ordering and insignificant whitespace. See README.
	encoded := []byte("defenseclaw-mxc-preparation-v1\x00")
	putString := func(value string) {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(value)))
		encoded = append(encoded, value...)
	}
	putStrings := func(values []string) {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(values)))
		for _, value := range values {
			putString(value)
		}
	}
	putString(p.Backend)
	putStrings(p.Argv)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(p.Environment)))
	for _, variable := range p.Environment {
		putString(variable.Name)
		putString(variable.Value)
	}
	putString(p.Workdir)
	putStrings(p.Filesystem.Read)
	putStrings(p.Filesystem.Write)
	putStrings(p.Filesystem.Deny)
	encoded = append(encoded, 1) // V1 requires Offline=true.
	if p.Terminal == nil {
		encoded = append(encoded, 0)
	} else {
		encoded = append(encoded, 1)
		encoded = binary.BigEndian.AppendUint16(encoded, p.Terminal.Rows)
		encoded = binary.BigEndian.AppendUint16(encoded, p.Terminal.Columns)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, p.TimeoutMS)
	encoded = binary.BigEndian.AppendUint32(encoded, p.OutputLimit)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (f Frame) Validate() error {
	if f.Version != Version || f.Sequence == 0 || f.Request == 0 || f.Binding.Validate() != nil {
		return ErrProtocol
	}
	payloads := 0
	for _, present := range []bool{f.Plan != nil, f.Data != nil, f.Size != nil, f.Result != nil, f.Failure != nil} {
		if present {
			payloads++
		}
	}
	switch f.Kind {
	case Prepare:
		if f.Plan == nil || payloads != 1 {
			return ErrProtocol
		}
		digest, err := PreparationDigest(*f.Plan)
		if err != nil || digest != f.Binding.PreparationHash {
			return ErrProtocol
		}
	case Input, Output:
		if f.Data == nil || payloads != 1 || len(f.Data.Bytes) == 0 || len(f.Data.Bytes) > MaxDataBytes ||
			f.Kind == Input && f.Data.Stream != "stdin" || f.Kind == Output && f.Data.Stream != "stdout" && f.Data.Stream != "stderr" {
			return ErrProtocol
		}
	case Resize:
		if f.Size == nil || payloads != 1 || !f.Size.valid() {
			return ErrProtocol
		}
	case Exited:
		if f.Result == nil || payloads != 1 {
			return ErrProtocol
		}
	case Failed:
		if f.Failure == nil || payloads != 1 {
			return ErrProtocol
		}
		switch f.Failure.Code {
		case "invalid_request", "unsupported", "preparation_failed", "launch_failed", "io_failed", "cleanup_failed":
		default:
			return ErrProtocol
		}
	case Launch, InputEOF, Cancel, Wait, Destroy, Prepared, Started, Destroyed:
		if payloads != 0 {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}
