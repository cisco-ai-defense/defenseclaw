// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procprobe

import "testing"

// TestUntruncateCommRecoversLongRuntimeNames covers the local model servers
// that /proc/<pid>/stat cannot name.
//
// The kernel keeps 15 bytes of comm, so ollama_llama_server arrives as
// ollama_llama_se. The local-model runtime table matches on exact name, so
// the two largest local inference servers on Linux never matched -- plane A
// raised neither local_model_runtime nor the heartbeat that gates on it.
//
// argv[0] is attacker-controlled, so the recovery only ever lengthens a name
// it already agrees with; anything else keeps comm.
func TestUntruncateCommRecoversLongRuntimeNames(t *testing.T) {
	for _, test := range []struct {
		name    string
		comm    string
		cmdline string
		want    string
	}{
		{
			name:    "ollama's server is truncated by exactly the limit",
			comm:    "ollama_llama_se",
			cmdline: "/usr/local/bin/ollama_llama_server --model /m.gguf",
			want:    "ollama_llama_server",
		},
		{
			name:    "text-generation-server",
			comm:    "text-generation",
			cmdline: "/opt/venv/bin/text-generation-server serve",
			want:    "text-generation-server",
		},
		{
			name:    "a short name is never rewritten",
			comm:    "ollama",
			cmdline: "/usr/bin/something-else-entirely",
			want:    "ollama",
		},
		{
			name:    "a hostile argv[0] that disagrees with comm is ignored",
			comm:    "sshd_child_pro",
			cmdline: "ollama_llama_server --pretend",
			want:    "sshd_child_pro",
		},
		{
			name:    "argv[0] that merely differs in case is not a prefix match",
			comm:    "Text-generation",
			cmdline: "/opt/text-generation-server serve",
			want:    "Text-generation",
		},
		{
			name:    "no cmdline leaves comm alone",
			comm:    "ollama_llama_se",
			cmdline: "",
			want:    "ollama_llama_se",
		},
		{
			name:    "argv[0] equal to comm changes nothing",
			comm:    "text-generation",
			cmdline: "text-generation",
			want:    "text-generation",
		},
		{
			name:    "a bare separator is not a name",
			comm:    "ollama_llama_se",
			cmdline: "/",
			want:    "ollama_llama_se",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := untruncateComm(test.comm, test.cmdline); got != test.want {
				t.Fatalf("untruncateComm(%q, %q) = %q, want %q",
					test.comm, test.cmdline, got, test.want)
			}
		})
	}
}

// The kernel constant this depends on. If TASK_COMM_LEN ever changes, the
// recovery silently stops firing, so state the assumption.
func TestCommTruncationLimitMatchesTaskCommLen(t *testing.T) {
	if commTruncationLimit != 15 {
		t.Fatalf("commTruncationLimit = %d, want 15 (TASK_COMM_LEN-1)", commTruncationLimit)
	}
}
