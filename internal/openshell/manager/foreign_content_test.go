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

package manager

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tarOf is the archive docker cp writes of one file.
func tarOf(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), ModTime: time.Unix(1700000000, 0), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// GAP-0689: the Claude Code binary copied to /usr/local/bin/cl2 and run in
// a plain label-free container ran no command named claude, so the
// container was never reported. It is found by its content (the package
// name its build carries, here split across two reads), through the
// docker CLI the daemon runs; a container that runs only ordinary programs
// is not, and a process read once is not read again.
func TestForeignContainerFoundByContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker CLI is a shell script")
	}
	dir := t.TempDir()
	agent := append(bytes.Repeat([]byte{0x7f}, contentChunk-10), []byte("..@anthropic-ai/claude-code/2.1.156..")...)
	for name, content := range map[string][]byte{
		"agent.tar": tarOf(t, "cl2", agent),
		"plain.tar": tarOf(t, "sleep", bytes.Repeat([]byte("sleep "), 4096)),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_DIR/calls"
case "$1" in
ps) printf 'c1\tcxr4-plain-nolabel:lab\tcxr4-neutral\t\nc2\tcxr4-plain-nolabel:lab\tcxr4-idle\tteam=dev\n' ;;
top) case "$2" in
  c1) printf 'PID COMMAND\n11 /bin/sh\n12 cl2\n' ;;
  c2) printf 'PID COMMAND\n21 sleep 600\n' ;;
  esac ;;
inspect) printf '{"Env":["PATH=/usr/local/bin:/usr/bin"],"WorkingDir":"/work"}\n' ;;
cp) case "$3" in
  c1:/usr/local/bin/cl2) cat "$FAKE_DOCKER_DIR/agent.tar" ;;
  c1:/bin/sh|c2:/usr/bin/sleep) cat "$FAKE_DOCKER_DIR/plain.tar" ;;
  *) echo "Error: No such container:path: $3" >&2; exit 1 ;;
  esac ;;
*) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_DIR", dir)
	t.Cleanup(func() {
		contentMu.Lock()
		clear(contentSeen)
		contentMu.Unlock()
	})

	found, err := dockerAgentContainers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != "c1" || found[0].Agent != "claudecode" || found[0].Image != "cxr4-plain-nolabel:lab" ||
		found[0].Name != "cxr4-neutral" {
		t.Fatalf("found %+v, want only c1 running claudecode", found)
	}
	calls := func() string {
		raw, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(raw)
	}
	first := strings.Count(calls(), "cp -L")
	if _, err := dockerAgentContainers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if again := strings.Count(calls(), "cp -L") - first; again != 0 {
		t.Fatalf("a second scan read %d files of processes already read:\n%s", again, calls())
	}

	// A command line that names the package is enough (node running a
	// renamed copy of the npm build's script), with no file read.
	contentMu.Lock()
	h, uid := (&contentScan{}).agent("c9", "PID UID ARGS\n5 1000 node /opt/x/@anthropic-ai/claude-code/cli2.js\n", true)
	contentMu.Unlock()
	if h != "claudecode" || uid != 1000 {
		t.Fatalf("command line = %q, %d", h, uid)
	}
}
