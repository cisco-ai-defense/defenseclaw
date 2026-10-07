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
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"reflect"
	"strings"
	"testing"
)

// The request names the operation and the protocol and nothing else: what a
// reader sees is decided by the kernel's credentials of its connection.
func TestRequestIsFieldless(t *testing.T) {
	if n := reflect.TypeOf(Request{}).NumField(); n != 2 {
		t.Fatalf("Request has %d fields, want version and op only", n)
	}
	data, err := json.Marshal(Request{Version: ProtocolVersion, Op: OpSandboxExecs})
	if err != nil || string(data) != `{"version":1,"op":"sandbox_execs"}` {
		t.Fatalf("request = %s, %v", data, err)
	}
}

// A gateway reads its own protocol and the one before it, and no other.
func TestProtocolSkewWindow(t *testing.T) {
	for _, c := range []struct {
		client, server int
		want           bool
	}{
		{1, 1, true}, {1, 0, false}, {1, 2, false},
		{2, 2, true}, {2, 1, true}, {2, 3, false}, {3, 1, false},
	} {
		if got := acceptsFor(c.client, c.server); got != c.want {
			t.Errorf("client %d reads server %d = %v, want %v", c.client, c.server, got, c.want)
		}
	}
	skew := &SkewError{Server: 3, Client: 1, Build: "9.9.9"}
	if !errors.Is(skew, ErrVersionSkew) || ReasonFor(fmt.Errorf("dial: %w", skew)) != ReasonVersionSkew {
		t.Fatalf("a skew error is not ErrVersionSkew: %v", skew)
	}
}

func TestReasonFor(t *testing.T) {
	for err, want := range map[error]string{
		nil: "", ErrNotInstalled: ReasonNotInstalled, ErrNotPermitted: ReasonNotPermitted,
		ErrUntrusted: ReasonUntrusted, ErrUnsupported: ReasonUnsupported, errors.New("eof"): ReasonUnavailable,
	} {
		if got := ReasonFor(err); got != want {
			t.Errorf("ReasonFor(%v) = %q, want %q", err, got, want)
		}
	}
}

// The collector's shape, as the gateway runs it, possibly under timeout(1);
// a look-alike that does not start the same way is not the collector.
func TestIsCollectorCommand(t *testing.T) {
	collector := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/sandbox", "LC_ALL=C", "/bin/bash", "-p", "-c", "script", CollectorName, "ps"}
	for name, c := range map[string]struct {
		argv []string
		want bool
	}{
		"direct":              {collector, true},
		"cut after -c":        {collector[:8], true},
		"under timeout":       {append([]string{"/usr/bin/timeout", "10"}, collector...), true},
		"under a long option": {append([]string{"/usr/bin/timeout", "--kill-after=5", "10"}, collector...), true},
		"too deep":            {append([]string{"a", "b", "c", "d"}, collector...), false},
		"a workload shell":    {[]string{"/bin/bash", "-c", "env -i PATH=/usr/bin:/bin " + CollectorName}, false},
		"another PATH":        {append([]string{"/usr/bin/env", "-i", "PATH=/tmp/bin"}, collector[3:]...), false},
		"empty":               {nil, false},
	} {
		if got := IsCollectorCommand(c.argv); got != c.want {
			t.Errorf("%s: IsCollectorCommand = %v, want %v", name, got, c.want)
		}
	}
}

// The per-user gateway imports this package (the client and the lifecycle)
// and must never reach Tetragon's root-equivalent API: only the root feed
// (package feed) imports the Tetragon client.
func TestSharedPackageDoesNotImportTetragon(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, "sensor/tetragon") || strings.Contains(imp, "third_party/tetragon") || strings.HasSuffix(imp, "sandboxfeed/feed") {
			t.Fatalf("package sandboxfeed imports %s", imp)
		}
	}
}
