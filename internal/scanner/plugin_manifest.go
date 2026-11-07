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

package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// manifestEntrypointsTimeout bounds one DeclaredEntrypoints run.
const manifestEntrypointsTimeout = 60 * time.Second

// manifestEntrypointsCommand is the command that prints the entrypoints the
// plugin scanner reads from manifests sent on stdin, for the launcher this
// scanner runs through. The standalone defenseclaw-plugin-scanner program
// has no such command.
func (s *PluginScanner) manifestEntrypointsCommand() (string, []string, error) {
	binaryPath := s.BinaryPath
	if binaryPath == "" {
		binaryPath = "defenseclaw"
	}
	switch filepath.Base(binaryPath) {
	case "defenseclaw-plugin-scanner", "defenseclaw-plugin-scanner.exe":
		return "", nil, fmt.Errorf("scanner: %s cannot list manifest entrypoints", filepath.Base(binaryPath))
	case scannerRuntimeName, scannerRuntimeName + ".exe":
		return binaryPath, []string{"plugin-manifest-entrypoints"}, nil
	}
	return binaryPath, []string{"plugin", "manifest-entrypoints"}, nil
}

// DeclaredEntrypoints returns the entrypoints the plugin scanner itself reads
// from manifests, given as a candidate path (slash-separated, for example
// "plugin.yaml") mapped to the bytes the caller read once. The scanner is the
// only reader of the manifest grammar, so a caller that must know which files
// a scan can read asks it instead of parsing the same text a second time. A
// manifest the scanner refuses declares nothing. An error means the scanner
// could not answer, which includes a reply that carries no entrypoints list,
// and the caller must not treat that as "declares nothing".
func (s *PluginScanner) DeclaredEntrypoints(ctx context.Context, manifests map[string][]byte) ([]string, error) {
	binaryPath, args, err := s.manifestEntrypointsCommand()
	if err != nil {
		return nil, err
	}
	if err := scannerRuntimePreflight(s.BinaryPath, "defenseclaw", "defenseclaw.exe"); err != nil {
		return nil, err
	}
	encoded := make(map[string]string, len(manifests))
	for name, data := range manifests {
		encoded[name] = base64.StdEncoding.EncodeToString(data)
	}
	request, err := json.Marshal(map[string]any{"manifests": encoded})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, manifestEntrypointsTimeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, binaryPath, args...)
	cmd.Env = append(os.Environ(), ScanRecordedByCallerEnv+"=1")
	if usesScannerRuntime(binaryPath) {
		cmd.Env = s.runtimeEnv(cmd.Env)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(request)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := runScannerCommand(cmd); err != nil {
		return nil, fmt.Errorf("scanner: list manifest entrypoints: %w (stderr=%s)", err, scannerFailureText(stderr.String()))
	}
	var reply struct {
		Entrypoints *[]*string `json:"entrypoints"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		return nil, fmt.Errorf("scanner: list manifest entrypoints: %w", err)
	}
	// A reply with no entrypoints member (or null) is not an answer: only an
	// explicit empty list says that no manifest declares a file.
	if reply.Entrypoints == nil {
		return nil, errors.New("scanner: list manifest entrypoints: the reply has no entrypoints list")
	}
	// A null element is a malformed list, not an empty entrypoint.
	entrypoints := make([]string, 0, len(*reply.Entrypoints))
	for _, entrypoint := range *reply.Entrypoints {
		if entrypoint == nil {
			return nil, errors.New("scanner: list manifest entrypoints: the entrypoints list holds a null element")
		}
		entrypoints = append(entrypoints, *entrypoint)
	}
	return entrypoints, nil
}
