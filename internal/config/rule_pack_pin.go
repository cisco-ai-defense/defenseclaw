// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// rulePackPinnedPosture reads only the selected pack's own files. Its digest
// has the same path-and-content format as guardrail.RulePackDigest, without
// importing the rule loader into config. An unreadable or invalid inventory
// gives the standalone hook no permission to relax its outage tier. The
// posture comes from the same manifest bytes as the checked digest.
func rulePackPinnedPosture(dir, pin string) (string, bool) {
	digest, posture, err := rulePackPinDigest(dir)
	return posture, err == nil && strings.EqualFold(strings.TrimSpace(pin), "sha256:"+digest)
}

func rulePackPinDigest(dir string) (string, string, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", "", errors.New("rule-pack directory unavailable")
	}
	const (
		maxEntries    = 4096
		maxFiles      = 64
		maxFileBytes  = 1 << 20
		maxTotalBytes = 4 << 20
	)
	sums := make(map[string]string)
	posture := ""
	entries, files, total := 0, 0, int64(0)
	err = filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if full == root {
			return nil
		}
		entries++
		if entries > maxEntries || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("rule-pack inventory unavailable")
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		manifest := rulePackPinManifestName(rel)
		if entry.IsDir() {
			if manifest {
				return errors.New("rule-pack manifest unavailable")
			}
			return nil
		}
		if !manifest {
			extension := strings.ToLower(path.Ext(rel))
			if extension != ".yaml" && extension != ".yml" {
				return nil
			}
			if !rulePackPinYAMLName(rel) {
				return errors.New("rule-pack inventory unavailable")
			}
			files++
			if files > maxFiles {
				return errors.New("rule-pack inventory unavailable")
			}
		} else {
			rel = "defenseclaw-pack.json"
			if _, exists := sums[rel]; exists {
				return errors.New("rule-pack inventory unavailable")
			}
		}
		if !entry.Type().IsRegular() {
			return errors.New("rule-pack component unavailable")
		}
		fileInfo, err := entry.Info()
		if err != nil || fileInfo.Size() > maxFileBytes {
			return errors.New("rule-pack component unavailable")
		}
		handle, err := openRulePackPinFile(full)
		if err != nil {
			return err
		}
		openedInfo, err := handle.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxFileBytes {
			_ = handle.Close()
			return errors.New("rule-pack component unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(handle, maxFileBytes+1))
		_ = handle.Close()
		if err != nil || len(data) > maxFileBytes {
			return errors.New("rule-pack component unavailable")
		}
		if manifest {
			var value struct {
				Posture string `json:"posture"`
			}
			if json.Unmarshal(data, &value) != nil {
				return errors.New("rule-pack manifest unavailable")
			}
			switch named := strings.ToLower(strings.TrimSpace(value.Posture)); named {
			case HookPolicyTierDefault, HookPolicyTierStrict, HookPolicyTierPermissive:
				posture = named
			default:
				return errors.New("rule-pack manifest unavailable")
			}
		} else {
			total += int64(len(data))
			if total > maxTotalBytes {
				return errors.New("rule-pack component unavailable")
			}
		}
		sum := sha256.Sum256(data)
		sums[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return "", "", err
	}
	if files == 0 {
		return "", "", errors.New("rule-pack inventory unavailable")
	}
	rels := make([]string, 0, len(sums))
	for rel := range sums {
		rels = append(rels, rel)
	}
	slices.Sort(rels)
	hash := sha256.New()
	for _, rel := range rels {
		_, _ = fmt.Fprintf(hash, "%s\n%s\n", rel, sums[rel])
	}
	return hex.EncodeToString(hash.Sum(nil)), posture, nil
}

func rulePackPinManifestName(rel string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(rel, "defenseclaw-pack.json")
	}
	return rel == "defenseclaw-pack.json"
}

func rulePackPinYAMLName(rel string) bool {
	if path.Ext(rel) != ".yaml" {
		return false
	}
	switch rel {
	case "suppressions.yaml", "sensitive-tools.yaml", "rules/local-patterns.yaml":
		return true
	case "judge/exfil.yaml", "judge/injection.yaml", "judge/pii.yaml", "judge/tool-injection.yaml":
		return true
	}
	return path.Dir(rel) == "rules" && path.Base(rel) != "local-patterns.yaml"
}
