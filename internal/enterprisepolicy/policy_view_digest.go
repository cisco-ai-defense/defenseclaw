// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PolicyViewDigest binds the bytes of a connector's vendor machine policy
// sources to the administrator's protected runtime descriptor. It includes
// absent files and directory entries: hiding a policy file or introducing a
// higher-precedence source changes the digest. Both publication and each
// managed hook invocation use this exact reader, with a bounded file count
// and the existing trusted, bounded policy-file reader.
func PolicyViewDigest(opts Options, connector string) (string, error) {
	if opts.goos() != "linux" && opts.goos() != "darwin" {
		return "", fmt.Errorf("policy-view digest is unavailable on %s", opts.goos())
	}
	target, ok := TargetFor(connector)
	if !ok {
		return "", fmt.Errorf("%s has no machine-policy target", connector)
	}
	paths, err := target.Paths(opts)
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	add := func(path string) {
		if path != "" {
			seen[path] = true
		}
	}
	for _, path := range paths {
		add(path)
		// Claude and Copilot merge policy drop-ins in these folders.
		dir := filepath.Dir(path)
		switch filepath.Base(dir) {
		case "managed-settings.d", "policy.d":
			entries, err := os.ReadDir(dir)
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			if len(entries) > 128 {
				return "", fmt.Errorf("%s policy drop-in directory has too many entries", connector)
			}
			for _, entry := range entries {
				if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
					add(filepath.Join(dir, entry.Name()))
				}
			}
		}
	}
	if connector == ConnectorOpenCode && opts.OpenCodePluginPath != "" {
		add(opts.openCodeArtifactFile())
	}
	if opts.goos() == "darwin" {
		preference := ""
		switch connector {
		case ConnectorCodex:
			preference = "com.openai.codex.plist"
		case ConnectorClaudeCode:
			preference = "com.anthropic.claudecode.plist"
		}
		if preference != "" {
			root := rooted(opts, "/Library/Managed Preferences")
			add(filepath.Join(root, preference))
			matches, err := filepath.Glob(filepath.Join(root, "*", preference))
			if err != nil {
				return "", err
			}
			for _, match := range matches {
				add(match)
			}
		}
	}
	if len(seen) == 0 || len(seen) > 128 {
		return "", fmt.Errorf("%s policy view has %d sources; expected 1..128", connector, len(seen))
	}
	names := make([]string, 0, len(seen))
	for path := range seen {
		names = append(names, path)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, path := range names {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return "", fmt.Errorf("invalid machine-policy path %q", path)
		}
		data, exists, err := readPolicyFile(opts, path)
		if err != nil {
			return "", fmt.Errorf("read %s policy view: %w", connector, err)
		}
		digestField(digest, []byte(path))
		if exists {
			digestField(digest, []byte{1})
			digestField(digest, data)
		} else {
			digestField(digest, []byte{0})
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func digestField(h hash.Hash, data []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
}
