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

package openshell

import (
	"errors"
	"strings"
	"testing"
)

func TestEditTOMLPreservesDocument(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "already configured (the spike host)",
			in: `[openshell]
version = 2

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true

[openshell.drivers.docker.resource_admission]
enabled = false
`,
			want: `[openshell]
version = 2

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true

[openshell.drivers.docker.resource_admission]
enabled = false
`,
		},
		{
			name: "replace in place, append missing key and table",
			in: `# Operator notes stay.
[openshell]
version = 2 # schema

[openshell.drivers.docker]
  # keep the network
  network = "openshell"   # inline comment
  enable_bind_mounts = false    # was off

# Tail comment belongs to the next table.
[openshell.drivers.podman]
socket = "/run/podman.sock"
`,
			want: `# Operator notes stay.
[openshell]
version = 2 # schema

[openshell.drivers.docker]
  # keep the network
  network = "openshell"   # inline comment
  enable_bind_mounts = true    # was off
  allow_driver_config = true

[openshell.drivers.docker.resource_admission]
enabled = false

# Tail comment belongs to the next table.
[openshell.drivers.podman]
socket = "/run/podman.sock"
`,
		},
		{
			name: "only the schema version",
			in:   "[openshell]\nversion = 2\n",
			want: `[openshell]
version = 2

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true

[openshell.drivers.docker.resource_admission]
enabled = false
`,
		},
		{
			name: "string and array content is not structure",
			in: `[openshell]
version = 2
banner = """
[openshell.drivers.docker]
enable_bind_mounts = false
"""
paths = [
  "[openshell.drivers.docker]", # not a header
  'enable_bind_mounts = false',
]
motd = '''
allow_driver_config = false'''
`,
			want: `[openshell]
version = 2
banner = """
[openshell.drivers.docker]
enable_bind_mounts = false
"""
paths = [
  "[openshell.drivers.docker]", # not a header
  'enable_bind_mounts = false',
]
motd = '''
allow_driver_config = false'''

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true

[openshell.drivers.docker.resource_admission]
enabled = false
`,
		},
		{
			name: "sub-table defined before its parent",
			in: `[openshell]
version = 2

[openshell.drivers.docker.resource_admission]
enabled = true
max_cpu = 4
`,
			want: `[openshell]
version = 2

[openshell.drivers.docker.resource_admission]
enabled = false
max_cpu = 4

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true
`,
		},
		{
			name: "spaced and quoted header keys",
			in: `[openshell]
version = 2
[ openshell . drivers . "docker" ]
"enable_bind_mounts" = false
`,
			want: `[openshell]
version = 2
[ openshell . drivers . "docker" ]
"enable_bind_mounts" = true
allow_driver_config = true

[openshell.drivers.docker.resource_admission]
enabled = false
`,
		},
		{
			name: "no trailing newline",
			in:   "[openshell]\nversion = 2",
			want: "[openshell]\nversion = 2\n\n[openshell.drivers.docker]\nallow_driver_config = true\nenable_bind_mounts = true\n\n[openshell.drivers.docker.resource_admission]\nenabled = false\n",
		},
		{
			name: "crlf line endings",
			in:   "[openshell]\r\nversion = 2\r\n[openshell.drivers.docker]\r\nenable_bind_mounts = false\r\n",
			want: "[openshell]\r\nversion = 2\r\n[openshell.drivers.docker]\r\nenable_bind_mounts = true\r\nallow_driver_config = true\r\n\r\n[openshell.drivers.docker.resource_admission]\r\nenabled = false\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := editTOML([]byte(tc.in), bindMountSettings)
			if err != nil {
				t.Fatalf("editTOML: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tc.want)
			}
			again, err := editTOML(got, bindMountSettings)
			if err != nil || string(again) != string(got) {
				t.Fatalf("editing twice changed the document: %v\n%s", err, again)
			}
		})
	}
}

func TestEditTOMLRefusesUnsafeShapes(t *testing.T) {
	cases := map[string]string{
		"dotted keys in parent": "[openshell]\nversion = 2\n[openshell.drivers]\ndocker.enable_bind_mounts = false\n",
		"inline table":          "[openshell]\nversion = 2\ndrivers = { docker = { enable_bind_mounts = false } }\n",
		"multi-line value":      "[openshell]\nversion = 2\n[openshell.drivers.docker]\nenable_bind_mounts = [\n  true,\n]\n",
		"array of tables":       "[openshell]\nversion = 2\n[[openshell.drivers.docker]]\nname = \"a\"\n",
		"root dotted keys":      "openshell.version = 2\nopenshell.drivers.docker.enable_bind_mounts = false\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := editTOML([]byte(in), bindMountSettings); !errors.Is(err, ErrTOMLEdit) {
				t.Fatalf("err = %v, want ErrTOMLEdit", err)
			}
		})
	}
	if _, err := editTOML([]byte("[openshell\n"), bindMountSettings); err == nil || errors.Is(err, ErrTOMLEdit) {
		t.Fatalf("malformed input: err = %v, want a parse error", err)
	}
}

func TestLineDiff(t *testing.T) {
	got := strings.Join(lineDiff("a\nb\nc\n", "a\nB\nc\nd\n"), "|")
	if got != "+ B|- b|+ d" && got != "- b|+ B|+ d" {
		t.Fatalf("lineDiff = %q", got)
	}
	if d := lineDiff("", "x\n"); len(d) != 1 || d[0] != "+ x" {
		t.Fatalf("lineDiff from empty = %q", d)
	}
}

func TestEditEnvFile(t *testing.T) {
	in := "# gateway overrides\nOPENSHELL_LOG_LEVEL=debug\n; legacy comment\nOPENSHELL_TELEMETRY_ENABLED=true\nOPENSHELL_DB_URL=\"postgres://u:p@h/db\"\nOPENSHELL_TELEMETRY_ENABLED=1\n"
	out, summary, err := editEnvFile([]byte(in), map[string]string{"OPENSHELL_TELEMETRY_ENABLED": "false", "OPENSHELL_NOTE": "two words"}, []string{"OPENSHELL_LOG_LEVEL"})
	if err != nil {
		t.Fatal(err)
	}
	want := "# gateway overrides\n; legacy comment\nOPENSHELL_TELEMETRY_ENABLED=false\nOPENSHELL_DB_URL=\"postgres://u:p@h/db\"\nOPENSHELL_TELEMETRY_ENABLED=false\nOPENSHELL_NOTE=\"two words\"\n"
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	if strings.Join(summary, ",") != `OPENSHELL_NOTE="two words",OPENSHELL_TELEMETRY_ENABLED=false,unset OPENSHELL_LOG_LEVEL` {
		t.Fatalf("summary = %q", summary)
	}
	env := parseEnvFile(out)
	if env["OPENSHELL_NOTE"] != "two words" || env["OPENSHELL_DB_URL"] != "postgres://u:p@h/db" || env["OPENSHELL_TELEMETRY_ENABLED"] != "false" {
		t.Fatalf("parsed = %v", env)
	}
	if _, ok := env["OPENSHELL_LOG_LEVEL"]; ok {
		t.Fatal("unset key survived")
	}

	same, summary, err := editEnvFile(out, map[string]string{"OPENSHELL_TELEMETRY_ENABLED": "false"}, nil)
	if err != nil || string(same) != string(out) || len(summary) != 0 {
		t.Fatalf("no-op edit changed the file: %v %q %q", err, same, summary)
	}
	for name, tc := range map[string]struct {
		set   map[string]string
		unset []string
	}{
		"bad name":     {set: map[string]string{"1BAD": "x"}},
		"newline":      {set: map[string]string{"OK": "a\nb"}},
		"set and drop": {set: map[string]string{"OK": "x"}, unset: []string{"OK"}},
		"bad unset":    {unset: []string{"a-b"}},
	} {
		if _, _, err := editEnvFile(nil, tc.set, tc.unset); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
