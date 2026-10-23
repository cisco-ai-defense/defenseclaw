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
// higher-precedence shared source changes the digest. Per-account macOS
// preferences are pinned separately for the invoking account. Both
// publication and each managed hook invocation use this exact reader, with a
// bounded file count and the existing trusted, bounded policy-file reader.
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
	}
	// skipIfUntrusted holds the Copilot drop-ins other than DefenseClaw's
	// own: Copilot, and the Copilot reader, skip one it does not trust.
	skipIfUntrusted := make(map[string]bool)
	for _, path := range paths {
		// Claude and Copilot merge policy drop-ins in these folders. Only
		// the entries their vendor readers load are policy: a hidden or
		// non-JSON entry (an editor's or MDM agent's draft, a backup) is
		// neither hashed nor counted (review loop round 2, P2).
		dir := filepath.Dir(path)
		switch filepath.Base(dir) {
		case "managed-settings.d", "policy.d":
			entries, err := os.ReadDir(platformPath(opts, dir))
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			dropIns := 0
			for _, entry := range entries {
				if !effectivePolicyDropIn(entry) {
					continue
				}
				if dropIns++; dropIns > 128 {
					return "", fmt.Errorf("%s policy drop-in directory has too many policy files", connector)
				}
				child := filepath.Join(dir, entry.Name())
				if connector == ConnectorCopilot && !seen[child] {
					skipIfUntrusted[child] = true
				}
				add(child)
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
		if err != nil && skipIfUntrusted[path] {
			// Copilot does not load it; record only that it is there, so
			// it becoming trusted still changes the digest.
			digestField(digest, []byte(path))
			digestField(digest, []byte{2})
			continue
		}
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

// effectivePolicyDropIn reports whether a vendor loads entry from a merged
// policy drop-in folder (Claude Code's managed-settings.d, Copilot's
// policy.d): a visible, non-directory .json entry. The vendor policy
// readers, the guard and cleanup scans and the policy-view digest all use
// it, so none of them treats an ignored entry as policy.
func effectivePolicyDropIn(entry os.DirEntry) bool {
	name := entry.Name()
	return !entry.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(strings.ToLower(name), ".json")
}

func digestField(h hash.Hash, data []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
}
