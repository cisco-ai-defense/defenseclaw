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

//go:build !windows

package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseDarwinPSProcessLinePreservesLongExecutableAliases(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		line           string
		executablePath string
		wantComm       string
		wantUser       string
	}{
		{
			name:           "AnythingLLM app bundle and model argument contain spaces",
			line:           `101 1 alice 01:02:03 /Applications/AnythingLLM Desktop.app/Contents/MacOS/anythingllm-desktop --model "/Users/alice/AI Models/model.gguf"`,
			executablePath: "/Applications/AnythingLLM Desktop.app/Contents/MacOS/anythingllm-desktop",
			wantComm:       "anythingllm-desktop",
			wantUser:       "alice",
		},
		{
			name:           "KoboldCpp path and arguments contain spaces",
			line:           `102 101 alice 00:00:05 /Users/alice/AI Tools/koboldcpp-mac-arm64 --model /Users/alice/My Models/story.gguf`,
			executablePath: "/Users/alice/AI Tools/koboldcpp-mac-arm64",
			wantComm:       "koboldcpp-mac-arm64",
			wantUser:       "alice",
		},
		{
			name:     "parenthesized kernel process name",
			line:     "301 1 root 00:10 (mdworker)",
			wantComm: "mdworker",
			wantUser: "root",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, ok := parseDarwinPSProcessLine(context.Background(), test.line, now, func(candidate string) bool {
				return candidate == test.executablePath
			})
			if !ok {
				t.Fatal("Darwin ps row was rejected")
			}
			if info.Comm != test.wantComm {
				t.Fatalf("executable basename = %q, want %q", info.Comm, test.wantComm)
			}
			if info.PID <= 0 || info.User != test.wantUser {
				t.Fatalf("process metadata not preserved: %+v", info)
			}
		})
	}
}

func TestDarwinExecutableBasenameDoesNotMatchArguments(t *testing.T) {
	commandLine := "/usr/bin/open /Applications/AnythingLLM.app/Contents/MacOS/anythingllm-desktop"
	got := darwinExecutableBasename(context.Background(), commandLine, func(candidate string) bool {
		return candidate == "/usr/bin/open"
	})
	if got != "open" {
		t.Fatalf("executable basename = %q, want open", got)
	}
}

func TestDarwinExecutableBasenameFallbacks(t *testing.T) {
	tests := []struct {
		name        string
		commandLine string
		want        string
	}{
		{
			name:        "bundle executable matches spaced bundle name",
			commandLine: "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook --reopen-window",
			want:        "microsoft outlook",
		},
		{
			name:        "bundle executable differs from bundle name",
			commandLine: "/Applications/AnythingLLM.app/Contents/MacOS/anythingllm-desktop --serve",
			want:        "anythingllm-desktop",
		},
		{
			name:        "quoted executable path",
			commandLine: `"/Applications/AnythingLLM Desktop.app/Contents/MacOS/anythingllm-desktop" --serve`,
			want:        "anythingllm-desktop",
		},
		{
			name:        "ordinary command",
			commandLine: "koboldcpp-mac-arm64 --model story.gguf",
			want:        "koboldcpp-mac-arm64",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := darwinExecutableBasename(context.Background(), test.commandLine, func(string) bool { return false }); got != test.want {
				t.Fatalf("executable basename = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDarwinExecutableBasenameBoundsPathProbes(t *testing.T) {
	commandLine := "/" + strings.Repeat("missing path component ", darwinExecutableProbeCandidates+20) + "--argument"
	probes := 0
	darwinExecutableBasename(context.Background(), commandLine, func(string) bool {
		probes++
		return false
	})
	if probes != darwinExecutableProbeCandidates {
		t.Fatalf("executable path probes = %d, want %d", probes, darwinExecutableProbeCandidates)
	}
}

func TestParseDarwinPSProcessLineRejectsMalformedRows(t *testing.T) {
	now := time.Now()
	for _, line := range []string{
		"",
		"101 1 alice 00:01",
		"not-a-pid 1 alice 00:01 anythingllm-desktop",
	} {
		if info, ok := parseDarwinPSProcessLine(context.Background(), line, now, func(string) bool { return false }); ok {
			t.Errorf("malformed row accepted as %+v: %q", info, line)
		}
	}
}

func TestParseDarwinPSOutputBoundsLongLinesAndPreservesFraming(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	longArguments := " --payload=" + strings.Repeat("x", darwinProcessReadBufferBytes+256)
	firstRow := "101 1 alice 00:01 anythingllm-desktop" + longArguments
	if len(firstRow) <= darwinProcessReadBufferBytes {
		t.Fatalf("long Darwin process row = %d bytes, want more than %d", len(firstRow), darwinProcessReadBufferBytes)
	}
	input := strings.Join([]string{
		firstRow,
		"102 1 alice 00:02 superwhisper --background",
		"103 1 alice 00:03 /opt/homebrew/bin/llama-server --serve",
		"",
	}, "\n")
	infos, err := parseDarwinPSOutputWithLimits(
		context.Background(), strings.NewReader(input), now, func(string) bool { return false },
		darwinProcessOutputLimits{totalBytes: len(input) + 1, lineBytes: 96},
	)
	if err != nil {
		t.Fatalf("parse bounded Darwin output: %v", err)
	}
	if len(infos) != 3 || infos[0].Comm != "anythingllm-desktop" || infos[1].Comm != "superwhisper" ||
		infos[2].Comm != "llama-server" {
		t.Fatalf("bounded Darwin output lost row framing: %+v", infos)
	}
}

func TestParseDarwinPSOutputRejectsTotalOutputOverflow(t *testing.T) {
	_, err := parseDarwinPSOutputWithLimits(
		context.Background(), strings.NewReader(strings.Repeat("x", 257)), time.Now(),
		func(string) bool { return false },
		darwinProcessOutputLimits{totalBytes: 128, lineBytes: 32},
	)
	if !errors.Is(err, errDarwinProcessOutputLimit) {
		t.Fatalf("total output overflow error = %v, want %v", err, errDarwinProcessOutputLimit)
	}
}

func TestDarwinExecutableResolutionStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	probes := 0
	got := darwinExecutableBasename(
		ctx,
		"/Applications/AnythingLLM Desktop.app/Contents/MacOS/anythingllm-desktop --serve",
		func(string) bool {
			probes++
			return true
		},
	)
	if got != "" || probes != 0 {
		t.Fatalf("expired executable resolution = %q with %d probes, want empty/zero", got, probes)
	}
	_, err := parseDarwinPSOutputWithLimits(
		ctx, strings.NewReader("101 1 alice 00:01 superwhisper\n"), time.Now(),
		func(string) bool { probes++; return true },
		darwinProcessOutputLimits{totalBytes: 128, lineBytes: 64},
	)
	if !errors.Is(err, context.DeadlineExceeded) || probes != 0 {
		t.Fatalf("expired output parse error/probes = %v/%d", err, probes)
	}
}

func TestDarwinExecutableResolutionStopsBetweenCandidateProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probes := 0
	got := firstExecutableCommandPrefix(ctx, "/missing path with spaces --serve", func(string) bool {
		probes++
		cancel()
		return false
	})
	if got != "" || probes != 1 {
		t.Fatalf("canceled prefix resolution = %q with %d probes, want empty/one", got, probes)
	}
}

func TestParseStandardPSProcessLinePreservesNonDarwinLayout(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	info, ok := parseStandardPSProcessLine("201 1 alice /opt/ai/anythingllm-desktop 02:03", now)
	if !ok {
		t.Fatal("standard ps row was rejected")
	}
	if info.Comm != "anythingllm-desktop" || info.PID != 201 || info.PPID != 1 || info.User != "alice" {
		t.Fatalf("unexpected standard ps result: %+v", info)
	}
	if want := now.Add(-(2*time.Minute + 3*time.Second)); !info.StartedAt.Equal(want) {
		t.Fatalf("started at = %s, want %s", info.StartedAt, want)
	}
}
