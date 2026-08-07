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

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

const (
	sgwMCPProtocolVersion = "2025-06-18"
	sgwTokenizerToolName  = "sgw_prepare_proxy_tokenization"
	sgwRunnerServerName   = "s-gw-core"
	sgwRunnerVersion      = "0.2.0"
	sgwMCPMaxFrameBytes   = 8 * 1024 * 1024
	sgwMCPMaxStderrBytes  = 1024 * 1024
	sgwMCPStartupTimeout  = 5 * time.Second
)

var errSGWMCPProtocol = errors.New("s-gw credential broker protocol error")

type sgwToolCaller interface {
	CallTool(context.Context, string, any) ([]byte, error)
	Close() error
}

type sgwCredentialTokenizer struct {
	client sgwToolCaller
}

func newSGWCredentialTokenizer(client sgwToolCaller) (*sgwCredentialTokenizer, error) {
	if client == nil {
		return nil, errors.New("s-gw credential broker client is unavailable")
	}
	return &sgwCredentialTokenizer{client: client}, nil
}

func (s *sgwCredentialTokenizer) PrepareProxyTokenization(
	ctx context.Context,
	request CredentialTokenizationRequest,
) (CredentialTokenizationResult, error) {
	if s == nil || s.client == nil {
		return CredentialTokenizationResult{}, errors.New("s-gw credential broker is unavailable")
	}
	raw, err := s.client.CallTool(ctx, sgwTokenizerToolName, request)
	if err != nil {
		return CredentialTokenizationResult{}, errors.New("s-gw credential broker call failed")
	}
	return decodeCredentialTokenizationResult(raw)
}

func (s *sgwCredentialTokenizer) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func decodeCredentialTokenizationResult(raw []byte) (CredentialTokenizationResult, error) {
	if len(raw) == 0 || len(raw) > sgwMCPMaxFrameBytes {
		return CredentialTokenizationResult{}, errSGWMCPProtocol
	}
	var result CredentialTokenizationResult
	if err := decodeSGWJSON(raw, &result, true); err != nil {
		return CredentialTokenizationResult{}, errSGWMCPProtocol
	}
	return result, nil
}

type sgwMCPProcess struct {
	process sgwChildProcess
	stdin   io.WriteCloser
	stdout  *bufio.Reader

	callMu sync.Mutex
	nextID atomic.Int64

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
}

type sgwChildProcess interface {
	Kill() error
	Wait() error
}

type sgwAdmittedCommand struct {
	process sgwChildProcess
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

type sgwExecProcess struct {
	cmd *exec.Cmd
}

func (p *sgwExecProcess) Kill() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

func (p *sgwExecProcess) Wait() error {
	if p == nil || p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}

type sgwRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type sgwRPCNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type sgwRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func startSGWMCPProcess(command string, args, env []string, cwd string) (*sgwMCPProcess, error) {
	if command == "" || cwd == "" {
		return nil, errors.New("s-gw credential broker command is invalid")
	}
	cmd := exec.Command(command, args...)
	cmd.Dir = cwd
	cmd.Env = append([]string(nil), env...)
	return startSGWMCPCommand(cmd)
}

func startSGWMCPCommand(cmd *exec.Cmd) (*sgwMCPProcess, error) {
	child, err := startSGWCommand(cmd)
	if err != nil {
		return nil, err
	}
	return initializeSGWMCPProcess(child.process, child.stdin, child.stdout, child.stderr)
}

func startSGWCommand(cmd *exec.Cmd) (*sgwAdmittedCommand, error) {
	if cmd == nil || cmd.Path == "" || cmd.Dir == "" {
		return nil, errors.New("s-gw credential broker command is invalid")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("create s-gw credential broker input")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create s-gw credential broker output")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create s-gw credential broker diagnostics")
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, errors.New("start s-gw credential broker")
	}
	return &sgwAdmittedCommand{
		process: &sgwExecProcess{cmd: cmd},
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

func initializeSGWMCPProcess(
	child sgwChildProcess,
	stdin io.WriteCloser,
	stdout io.Reader,
	stderr io.Reader,
) (*sgwMCPProcess, error) {
	if child == nil || stdin == nil || stdout == nil || stderr == nil {
		return nil, errors.New("s-gw credential broker process is invalid")
	}
	process := &sgwMCPProcess{
		process: child,
		stdin:   stdin,
		stdout:  bufio.NewReaderSize(stdout, 64*1024),
		closed:  make(chan struct{}),
	}
	go process.discardStderr(stderr)

	ctx, cancel := context.WithTimeout(context.Background(), sgwMCPStartupTimeout)
	defer cancel()
	var initialized struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions,omitempty"`
	}
	params := map[string]any{
		"protocolVersion": sgwMCPProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name":    "defenseclaw",
			"version": version.Current().BinaryVersion,
		},
	}
	if err := process.call(ctx, "initialize", params, &initialized); err != nil {
		_ = process.Close()
		return nil, errors.New("initialize s-gw credential broker")
	}
	if initialized.ProtocolVersion != sgwMCPProtocolVersion {
		_ = process.Close()
		return nil, errSGWMCPProtocol
	}
	if initialized.ServerInfo.Name != sgwRunnerServerName ||
		initialized.ServerInfo.Version != sgwRunnerVersion {
		_ = process.Close()
		return nil, errSGWMCPProtocol
	}
	if err := process.notify("notifications/initialized", map[string]any{}); err != nil {
		_ = process.Close()
		return nil, errors.New("finish s-gw credential broker initialization")
	}
	if err := process.validateToolInventory(ctx); err != nil {
		_ = process.Close()
		return nil, err
	}
	return process, nil
}

func (p *sgwMCPProcess) validateToolInventory(ctx context.Context) error {
	var result struct {
		Tools      []map[string]json.RawMessage `json:"tools"`
		NextCursor string                       `json:"nextCursor,omitempty"`
	}
	if err := p.call(ctx, "tools/list", map[string]any{}, &result); err != nil {
		return errors.New("inspect s-gw credential broker tools")
	}
	if len(result.Tools) != 1 || result.NextCursor != "" {
		return errSGWMCPProtocol
	}
	var name string
	if raw := result.Tools[0]["name"]; len(raw) == 0 || json.Unmarshal(raw, &name) != nil {
		return errSGWMCPProtocol
	}
	if name != sgwTokenizerToolName {
		return errSGWMCPProtocol
	}
	return nil
}

func (p *sgwMCPProcess) CallTool(ctx context.Context, name string, arguments any) ([]byte, error) {
	if p == nil || name != sgwTokenizerToolName {
		return nil, errors.New("s-gw credential broker tool is unavailable")
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := p.call(ctx, "tools/call", map[string]any{
		"name":      name,
		"arguments": arguments,
	}, &result); err != nil {
		return nil, err
	}
	if result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" {
		return nil, errSGWMCPProtocol
	}
	raw := []byte(result.Content[0].Text)
	if len(raw) == 0 || len(raw) > sgwMCPMaxFrameBytes {
		return nil, errSGWMCPProtocol
	}
	return raw, nil
}

func (p *sgwMCPProcess) call(ctx context.Context, method string, params, result any) error {
	if p == nil {
		return errors.New("s-gw credential broker is unavailable")
	}
	p.callMu.Lock()
	defer p.callMu.Unlock()

	select {
	case <-p.closed:
		return errors.New("s-gw credential broker is closed")
	default:
	}

	id := p.nextID.Add(1)
	done := make(chan error, 1)
	go func() {
		done <- p.callBlocking(id, method, params, result)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = p.Close()
		<-done
		return ctx.Err()
	}
}

func (p *sgwMCPProcess) callBlocking(id int64, method string, params, result any) error {
	request := sgwRPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > sgwMCPMaxFrameBytes {
		return errSGWMCPProtocol
	}
	payload = append(payload, '\n')
	if err := writeAll(p.stdin, payload); err != nil {
		return errors.New("write s-gw credential broker request")
	}

	for {
		frame, err := readSGWFrame(p.stdout)
		if err != nil {
			return errors.New("read s-gw credential broker response")
		}
		var response sgwRPCResponse
		if err := decodeSGWJSON(frame, &response, true); err != nil || response.JSONRPC != "2.0" {
			return errSGWMCPProtocol
		}
		if len(response.ID) == 0 {
			if response.Method != "" {
				continue
			}
			return errSGWMCPProtocol
		}
		var responseID int64
		if err := json.Unmarshal(response.ID, &responseID); err != nil || responseID != id {
			return errSGWMCPProtocol
		}
		if len(response.Error) != 0 && string(response.Error) != "null" {
			return errors.New("s-gw credential broker returned an error")
		}
		if len(response.Result) == 0 || len(response.Result) > sgwMCPMaxFrameBytes {
			return errSGWMCPProtocol
		}
		if err := decodeSGWJSON(response.Result, result, true); err != nil {
			return errSGWMCPProtocol
		}
		return nil
	}
}

func (p *sgwMCPProcess) notify(method string, params any) error {
	p.callMu.Lock()
	defer p.callMu.Unlock()
	select {
	case <-p.closed:
		return errors.New("s-gw credential broker is closed")
	default:
	}
	payload, err := json.Marshal(sgwRPCNotification{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil || len(payload) > sgwMCPMaxFrameBytes {
		return errSGWMCPProtocol
	}
	return writeAll(p.stdin, append(payload, '\n'))
}

func (p *sgwMCPProcess) discardStderr(stderr io.Reader) {
	written, _ := io.CopyN(io.Discard, stderr, sgwMCPMaxStderrBytes+1)
	if written > sgwMCPMaxStderrBytes {
		_ = p.Close()
	}
}

func (p *sgwMCPProcess) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		close(p.closed)
		if p.stdin != nil {
			_ = p.stdin.Close()
		}
		if p.process != nil {
			_ = p.process.Kill()
			_ = p.process.Wait()
		}
	})
	return p.closeErr
}

func readSGWFrame(reader *bufio.Reader) ([]byte, error) {
	frame := make([]byte, 0, 4096)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(frame)+len(fragment) > sgwMCPMaxFrameBytes {
			return nil, errSGWMCPProtocol
		}
		frame = append(frame, fragment...)
		if err == nil {
			frame = bytes.TrimSuffix(frame, []byte{'\n'})
			frame = bytes.TrimSuffix(frame, []byte{'\r'})
			if len(frame) == 0 {
				return nil, errSGWMCPProtocol
			}
			return frame, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func decodeSGWJSON(raw []byte, target any, disallowUnknown bool) error {
	if len(raw) == 0 || len(raw) > sgwMCPMaxFrameBytes || rejectDuplicateJSONKeys(raw) != nil {
		return errSGWMCPProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return errSGWMCPProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errSGWMCPProtocol
	}
	return nil
}

var _ CredentialTokenizer = (*sgwCredentialTokenizer)(nil)
