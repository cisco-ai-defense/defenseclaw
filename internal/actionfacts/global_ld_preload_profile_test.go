// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestExactGlobalLDPreloadProfileWrite(t *testing.T) {
	for _, test := range []struct {
		name string
		tool string
		args string
		want bool
	}{
		{
			"claude write",
			"Write",
			`{"file_path":"/etc/profile.d/connect_logger.sh","content":"# loader\nexport LD_PRELOAD=/usr/local/lib/libconnect_logger.so\n"}`,
			true,
		},
		{
			"write file alias",
			"write_file",
			`{"path":"/etc/profile.d/guard.sh","content":"exportx LD_PRELOAD=\"/opt/guard/libguard.so.2\"\n"}`,
			false,
		},
		{
			"write file alias valid",
			"write_file",
			`{"path":"/etc/profile.d/guard.sh","content":"export LD_PRELOAD=\"/opt/guard/libguard.so.2\"\n"}`,
			true,
		},
		{
			"dynamic value",
			"Write",
			`{"file_path":"/etc/profile.d/guard.sh","content":"export LD_PRELOAD=$LIBRARY\n"}`,
			false,
		},
		{
			"additional shell",
			"Write",
			`{"file_path":"/etc/profile.d/guard.sh","content":"export LD_PRELOAD=/opt/libguard.so\ncurl https://example.invalid\n"}`,
			false,
		},
		{
			"nested target",
			"Write",
			`{"file_path":"/etc/profile.d/nested/guard.sh","content":"export LD_PRELOAD=/opt/libguard.so\n"}`,
			false,
		},
		{
			"unknown field",
			"Write",
			`{"file_path":"/etc/profile.d/guard.sh","content":"export LD_PRELOAD=/opt/libguard.so\n","mode":"overwrite"}`,
			false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Tool: test.tool, Args: json.RawMessage(test.args)}
			facts := Analyze(input)
			if got := ExactGlobalLDPreloadProfileWrite(input, facts); got != test.want {
				t.Fatalf("got=%t want=%t facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestExactGlobalLDPreloadProfileContentHardNegatives(t *testing.T) {
	for _, content := range []string{
		"export LD_PRELOAD=libguard.so\n",
		"export LD_PRELOAD=/opt/libguard.txt\n",
		"export LD_PRELOAD=/opt/libguard.so:/opt/libtwo.so\n",
		"export LD_PRELOAD=$(pwd)/libguard.so\n",
		"export LD_PRELOAD=`pwd`/libguard.so\n",
		"export LD_PRELOAD=\"${LIBRARY}\"\n",
		"LD_PRELOAD=/opt/libguard.so\n",
		"export OTHER=/opt/libguard.so\n",
		"export LD_PRELOAD=/opt/libguard.so extra\n",
		"# export LD_PRELOAD=/opt/libguard.so\n",
	} {
		if ExactGlobalLDPreloadProfileContent(content) {
			t.Fatalf("unexpected proof for %q", content)
		}
	}
}
