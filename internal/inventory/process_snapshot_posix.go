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
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	darwinExecutableProbeBytes      = 4 * 1024
	darwinExecutableProbeCandidates = 8
	darwinProcessLineBytes          = 8 * 1024
	darwinProcessOutputBytes        = 16 * 1024 * 1024
	darwinProcessReadBufferBytes    = 4 * 1024
)

var errDarwinProcessOutputLimit = errors.New("darwin process snapshot exceeded bounded output limit")

type darwinProcessOutputLimits struct {
	totalBytes int
	lineBytes  int
}

// platformProcessSnapshot preserves the existing macOS/Linux ps path.
func platformProcessSnapshot() ([]processInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if runtime.GOOS == "darwin" {
		// Darwin's kernel-backed ucomm is limited to 15 bytes, and relying on the
		// prior comm/ucomm layouts loses full executable aliases. Keep the
		// variable-width args field last, parse only argv[0], and immediately
		// discard argument tails through bounded streaming. Fixed arguments also
		// avoid routing process-controlled data through a shell.
		cmd := exec.CommandContext(ctx, "ps", "-axww", "-o", "pid=,ppid=,user=,etime=,args=")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		infos, parseErr := parseDarwinPSOutput(ctx, stdout, now, func(value string) bool {
			return isExecutableFile(ctx, value)
		})
		if parseErr != nil {
			// Stop ps before Wait when a deadline or an output bound terminates
			// parsing; otherwise the child could remain blocked on its closed pipe.
			cancel()
		}
		waitErr := cmd.Wait()
		if parseErr != nil {
			return nil, parseErr
		}
		if waitErr != nil {
			return nil, waitErr
		}
		return infos, nil
	}

	// Preserve the existing non-Darwin command, buffered output, and parser.
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,user=,comm=,etime=")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var infos []processInfo
	for _, line := range strings.Split(out.String(), "\n") {
		info, ok := parseStandardPSProcessLine(line, now)
		if ok {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func parseDarwinPSOutput(
	ctx context.Context,
	input io.Reader,
	now time.Time,
	executable func(string) bool,
) ([]processInfo, error) {
	return parseDarwinPSOutputWithLimits(ctx, input, now, executable, darwinProcessOutputLimits{
		totalBytes: darwinProcessOutputBytes,
		lineBytes:  darwinProcessLineBytes,
	})
}

func parseDarwinPSOutputWithLimits(
	ctx context.Context,
	input io.Reader,
	now time.Time,
	executable func(string) bool,
	limits darwinProcessOutputLimits,
) ([]processInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limits.totalBytes < 1 || limits.lineBytes < 1 {
		return nil, errDarwinProcessOutputLimit
	}
	reader := bufio.NewReaderSize(input, darwinProcessReadBufferBytes)
	totalBytes := 0
	infos := make([]processInfo, 0, 256)
	for {
		line, atEOF, err := readBoundedDarwinPSLine(ctx, reader, &totalBytes, limits)
		if err != nil {
			return nil, err
		}
		if len(line) > 0 {
			if info, ok := parseDarwinPSProcessLine(ctx, string(line), now, executable); ok {
				infos = append(infos, info)
			}
		}
		if atEOF {
			return infos, nil
		}
	}
}

// readBoundedDarwinPSLine retains only the prefix the executable parser can
// use while draining the remainder of an oversized argv row. This bounds both
// per-line memory and total process-controlled ps output without allowing one
// long command line to corrupt framing for later processes.
func readBoundedDarwinPSLine(
	ctx context.Context,
	reader *bufio.Reader,
	totalBytes *int,
	limits darwinProcessOutputLimits,
) ([]byte, bool, error) {
	line := make([]byte, 0, limits.lineBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fragment, err := reader.ReadSlice('\n')
		*totalBytes += len(fragment)
		if *totalBytes > limits.totalBytes {
			return nil, false, errDarwinProcessOutputLimit
		}
		if remaining := limits.lineBytes - len(line); remaining > 0 {
			if len(fragment) < remaining {
				remaining = len(fragment)
			}
			line = append(line, fragment[:remaining]...)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, false, ctxErr
		}
		switch err {
		case nil:
			return bytes.TrimSuffix(line, []byte{'\n'}), false, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(fragment) == 0 && len(line) == 0 {
				return nil, true, nil
			}
			return line, true, nil
		default:
			return nil, false, err
		}
	}
}

func parseStandardPSProcessLine(line string, now time.Time) (processInfo, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 5 {
		return processInfo{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return processInfo{}, false
	}
	ppid, _ := strconv.Atoi(fields[1])
	return processInfo{
		PID: pid, PPID: ppid, User: fields[2],
		Comm:      strings.ToLower(filepath.Base(strings.Join(fields[3:len(fields)-1], " "))),
		StartedAt: now.Add(-parsePsEtime(fields[len(fields)-1])),
	}, true
}

func parseDarwinPSProcessLine(ctx context.Context, line string, now time.Time, executable func(string) bool) (processInfo, bool) {
	if ctx.Err() != nil {
		return processInfo{}, false
	}
	fields, commandLine := splitPSFields(line, 4)
	if len(fields) != 4 || commandLine == "" {
		return processInfo{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return processInfo{}, false
	}
	comm := darwinExecutableBasename(ctx, commandLine, executable)
	if comm == "" || ctx.Err() != nil {
		return processInfo{}, false
	}
	ppid, _ := strconv.Atoi(fields[1])
	return processInfo{
		PID: pid, PPID: ppid, User: fields[2],
		Comm:      comm,
		StartedAt: now.Add(-parsePsEtime(fields[3])),
	}, true
}

// splitPSFields leaves the variable-width final field untouched. In
// particular, strings.Fields cannot be used for Darwin args output because an
// application bundle path and its executable may both contain spaces.
func splitPSFields(value string, count int) ([]string, string) {
	value = strings.TrimSpace(value)
	fields := make([]string, 0, count)
	offset := 0
	for len(fields) < count {
		for offset < len(value) && isPSWhitespace(value[offset]) {
			offset++
		}
		if offset == len(value) {
			return fields, ""
		}
		start := offset
		for offset < len(value) && !isPSWhitespace(value[offset]) {
			offset++
		}
		fields = append(fields, value[start:offset])
	}
	for offset < len(value) && isPSWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		return fields, ""
	}
	return fields, strings.TrimSpace(value[offset:])
}

func isPSWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// darwinExecutableBasename reduces a full ps args value to the executable
// basename used for signature matching. macOS ps does not quote argv
// boundaries, so existing absolute executable prefixes are checked first to
// distinguish a space in an app path from the start of its arguments.
func darwinExecutableBasename(ctx context.Context, commandLine string, executable func(string) bool) string {
	if ctx.Err() != nil {
		return ""
	}
	commandLine = strings.TrimSpace(commandLine)
	if commandLine == "" {
		return ""
	}
	commandLine = stripMatchingDarwinCommandParentheses(commandLine)
	if commandLine == "" {
		return ""
	}
	if quoted, ok := quotedFirstCommandArgument(commandLine); ok {
		if ctx.Err() != nil {
			return ""
		}
		return normalizedExecutableBasename(quoted)
	}
	if executable != nil && strings.HasPrefix(commandLine, "/") {
		if executablePath := firstExecutableCommandPrefix(ctx, commandLine, executable); executablePath != "" {
			return normalizedExecutableBasename(executablePath)
		}
	}
	if ctx.Err() != nil {
		return ""
	}
	if bundled := darwinBundleExecutableFallback(commandLine); bundled != "" {
		if ctx.Err() != nil {
			return ""
		}
		return normalizedExecutableBasename(bundled)
	}
	if ctx.Err() != nil {
		return ""
	}
	return normalizedExecutableBasename(firstCommandToken(commandLine))
}

func stripMatchingDarwinCommandParentheses(commandLine string) string {
	if len(commandLine) < 2 || commandLine[0] != '(' {
		return commandLine
	}
	depth := 0
	for offset := 0; offset < len(commandLine); offset++ {
		switch commandLine[offset] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if offset+1 < len(commandLine) && !isPSWhitespace(commandLine[offset+1]) {
					return commandLine
				}
				return strings.TrimSpace(commandLine[1:offset] + commandLine[offset+1:])
			}
			if depth < 0 {
				return commandLine
			}
		}
	}
	return commandLine
}

func firstExecutableCommandPrefix(ctx context.Context, commandLine string, executable func(string) bool) string {
	probeBytes := len(commandLine)
	if probeBytes > darwinExecutableProbeBytes {
		probeBytes = darwinExecutableProbeBytes
	}
	candidates := 0
	for offset := 0; offset < probeBytes; offset++ {
		if ctx.Err() != nil {
			return ""
		}
		if !isPSWhitespace(commandLine[offset]) || (offset > 0 && isPSWhitespace(commandLine[offset-1])) {
			continue
		}
		candidate := strings.TrimSpace(commandLine[:offset])
		if candidate == "" {
			continue
		}
		candidates++
		if executable(candidate) {
			if ctx.Err() == nil {
				return candidate
			}
			return ""
		}
		if ctx.Err() != nil {
			return ""
		}
		if candidates == darwinExecutableProbeCandidates {
			return ""
		}
	}
	if ctx.Err() == nil && len(commandLine) <= darwinExecutableProbeBytes &&
		candidates < darwinExecutableProbeCandidates {
		if executable(commandLine) && ctx.Err() == nil {
			return commandLine
		}
	}
	return ""
}

func isExecutableFile(ctx context.Context, value string) bool {
	if ctx.Err() != nil {
		return false
	}
	info, err := os.Stat(value)
	return ctx.Err() == nil && err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
}

// darwinBundleExecutableFallback handles a short race (for example, an app
// being removed between ps and stat) without treating a later app-path
// argument to an ordinary command as argv[0]. Existing paths are resolved by
// firstExecutableCommandPrefix before this deterministic fallback is used.
func darwinBundleExecutableFallback(commandLine string) string {
	if !looksLikeDarwinBundleCommand(commandLine) {
		return ""
	}
	const marker = "/Contents/MacOS/"
	markerOffset := strings.Index(commandLine, marker)
	if markerOffset < 0 {
		return ""
	}
	bundlePath := commandLine[:markerOffset]
	bundleBase := filepath.Base(bundlePath)
	bundleName := strings.TrimSuffix(bundleBase, filepath.Ext(bundleBase))
	remainder := commandLine[markerOffset+len(marker):]
	if bundleName != "" && strings.HasPrefix(remainder, bundleName) {
		afterName := remainder[len(bundleName):]
		if afterName == "" || isPSWhitespace(afterName[0]) {
			return bundleName
		}
	}
	candidate := firstCommandToken(remainder)
	if strings.Contains(candidate, "/") {
		return ""
	}
	return candidate
}

func looksLikeDarwinBundleCommand(commandLine string) bool {
	if strings.HasPrefix(commandLine, "/Applications/") ||
		strings.HasPrefix(commandLine, "/System/Applications/") ||
		strings.HasPrefix(commandLine, "/System/Library/") ||
		strings.HasPrefix(commandLine, "/Library/") ||
		strings.HasPrefix(commandLine, "/Volumes/") {
		return true
	}
	return strings.HasPrefix(commandLine, "/Users/") && strings.Contains(commandLine, "/Applications/")
}

func quotedFirstCommandArgument(value string) (string, bool) {
	if len(value) < 2 || (value[0] != '\'' && value[0] != '"') {
		return "", false
	}
	quote := value[0]
	var argument strings.Builder
	escaped := false
	for offset := 1; offset < len(value); offset++ {
		current := value[offset]
		if escaped {
			argument.WriteByte(current)
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current == quote {
			return argument.String(), true
		}
		argument.WriteByte(current)
	}
	return "", false
}

func firstCommandToken(value string) string {
	value = strings.TrimSpace(value)
	for offset := 0; offset < len(value); offset++ {
		if isPSWhitespace(value[offset]) {
			return value[:offset]
		}
	}
	return value
}

func normalizedExecutableBasename(value string) string {
	return strings.ToLower(filepath.Base(strings.TrimSpace(value)))
}

func parsePsEtime(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	days := 0
	if idx := strings.IndexByte(value, '-'); idx >= 0 {
		d, err := strconv.Atoi(value[:idx])
		if err != nil {
			return 0
		}
		days, value = d, value[idx+1:]
	}
	parts := strings.Split(value, ":")
	if len(parts) == 0 || len(parts) > 3 {
		return 0
	}
	values := make([]int, len(parts))
	for i := range parts {
		values[i], _ = strconv.Atoi(parts[i])
	}
	var hours, minutes, seconds int
	switch len(values) {
	case 3:
		hours, minutes, seconds = values[0], values[1], values[2]
	case 2:
		minutes, seconds = values[0], values[1]
	case 1:
		seconds = values[0]
	}
	return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
}
