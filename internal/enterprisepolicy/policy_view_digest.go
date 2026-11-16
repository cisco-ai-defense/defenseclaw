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
// preferences are pinned separately (PolicyViewUserPins). Publication pins
// it; the gateway recomputes it only when PolicyViewStamp changes, never on
// a hook call.
func PolicyViewDigest(opts Options, connector string) (string, error) {
	names, skipIfUntrusted, err := policyViewSources(opts, connector)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	for _, path := range names {
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

// PolicyViewStamp is a cheap change stamp of everything the policy-view
// proof reads for connectors, plus files (the runtime descriptor): the
// metadata of each source PolicyViewDigest hashes, of each drop-in folder
// and, on macOS, of each account's managed preference. It reads no policy
// bytes. Content writes change a file's change time, which no unprivileged
// call can set back, so an unchanged stamp means an unchanged view and the
// digests need not be recomputed. A source that can not be listed stamps
// its error, which changes when the error does.
func PolicyViewStamp(opts Options, connectors []string, files ...string) string {
	stamp := sha256.New()
	for _, path := range files {
		stampPath(stamp, path)
	}
	for _, connector := range connectors {
		digestField(stamp, []byte(connector))
		names, _, err := policyViewSources(opts, connector)
		if err != nil {
			digestField(stamp, []byte(err.Error()))
		}
		for _, path := range names {
			stampPath(stamp, platformPath(opts, path))
		}
		for _, path := range policyViewAccountSources(opts, connector) {
			stampPath(stamp, path)
		}
	}
	return hex.EncodeToString(stamp.Sum(nil))
}

func stampPath(h hash.Hash, path string) {
	digestField(h, []byte(path))
	info, err := os.Lstat(path)
	if err != nil {
		digestField(h, []byte(err.Error()))
		return
	}
	digestField(h, []byte(fmt.Sprintf("%v %d %d %s", info.Mode(), info.Size(), info.ModTime().UnixNano(), fileChangeStamp(info))))
}

// policyViewSources are the sorted sources PolicyViewDigest hashes for
// connector, and the Copilot drop-ins other than DefenseClaw's own, which
// Copilot skips when it does not trust them.
func policyViewSources(opts Options, connector string) ([]string, map[string]bool, error) {
	if opts.goos() != "linux" && opts.goos() != "darwin" {
		return nil, nil, fmt.Errorf("policy-view digest is unavailable on %s", opts.goos())
	}
	target, ok := TargetFor(connector)
	if !ok {
		return nil, nil, fmt.Errorf("%s has no machine-policy target", connector)
	}
	paths, err := target.Paths(opts)
	if err != nil {
		return nil, nil, err
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
				return nil, nil, err
			}
			dropIns := 0
			for _, entry := range entries {
				if !effectivePolicyDropIn(entry) {
					continue
				}
				if dropIns++; dropIns > 128 {
					return nil, nil, fmt.Errorf("%s policy drop-in directory has too many policy files", connector)
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
			add(filepath.Join(rooted(opts, "/Library/Managed Preferences"), preference))
		}
	}
	if len(seen) == 0 || len(seen) > 128 {
		return nil, nil, fmt.Errorf("%s policy view has %d sources; expected 1..128", connector, len(seen))
	}
	names := make([]string, 0, len(seen))
	for path := range seen {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return nil, nil, fmt.Errorf("invalid machine-policy path %q", path)
		}
		names = append(names, path)
	}
	sort.Strings(names)
	return names, skipIfUntrusted, nil
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
