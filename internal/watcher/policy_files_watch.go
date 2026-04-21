// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// watchPolicyListsAndYAML polls policy-related files and emits EventActivity +
// audit LogActivity when block_list.yaml, allow_list.yaml, or policy/rego files change.
func (w *InstallWatcher) watchPolicyListsAndYAML(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.pollPolicyFilesOnce(ctx)
		}
	}
}

func (w *InstallWatcher) pollPolicyFilesOnce(ctx context.Context) {
	paths := w.policyWatchPaths()
	if len(paths) == 0 {
		return
	}
	type snap struct {
		hash string
		keys []string
	}
	next := make(map[string]snap, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				next[p] = snap{hash: "", keys: nil}
				continue
			}
			return
		}
		sum := sha256.Sum256(b)
		next[p] = snap{
			hash: hex.EncodeToString(sum[:]),
			keys: listKeysFromYAMLBytes(b),
		}
	}

	w.policyFileMu.Lock()
	defer w.policyFileMu.Unlock()
	if len(w.policyFileHashes) == 0 {
		for p, s := range next {
			w.policyFileHashes[p] = s.hash
			w.policyListSnap[p] = s.keys
		}
		return
	}

	var changed []string
	for p, s := range next {
		if w.policyFileHashes[p] != s.hash {
			changed = append(changed, p)
		}
	}
	for p := range w.policyFileHashes {
		if _, ok := next[p]; !ok {
			changed = append(changed, p)
		}
	}
	if len(changed) == 0 {
		return
	}

	gen := version.BumpGeneration()
	if w.otel != nil {
		w.otel.RecordProvenanceBump(ctx, "policy_files")
	}

	for _, p := range changed {
		s, ok := next[p]
		if !ok {
			prevHash := w.policyFileHashes[p]
			prevKeys := w.policyListSnap[p]
			diff := diffPolicySnapshot(prevHash, "", prevKeys, nil)
			targetID := filepath.Base(p)
			_ = w.logger.LogActivity(audit.ActivityInput{
				Actor:      "watcher",
				Action:     audit.ActionPolicyReload,
				TargetType: "policy_file",
				TargetID:   targetID,
				Reason:     "on-disk policy or list file removed",
				Diff:       diff,
				VersionTo:  fmt.Sprintf("gen=%d", gen),
			})
			if w.otel != nil {
				w.otel.RecordActivity(ctx, string(audit.ActionPolicyReload), "policy_file", "watcher", len(diff))
				w.otel.EmitGatewayEvent(gatewaylog.Event{
					Timestamp: time.Now().UTC(),
					EventType: gatewaylog.EventActivity,
					Severity:  gatewaylog.SeverityInfo,
					Activity: &gatewaylog.ActivityPayload{
						Actor:      "watcher",
						Action:     string(audit.ActionPolicyReload),
						TargetType: "policy_file",
						TargetID:   targetID,
						Reason:     "on-disk policy or list file removed",
						Diff:       activityDiffFromAudit(diff),
					},
				})
			}
			delete(w.policyFileHashes, p)
			delete(w.policyListSnap, p)
			continue
		}
		prevHash := w.policyFileHashes[p]
		prevKeys := w.policyListSnap[p]
		diff := diffPolicySnapshot(prevHash, s.hash, prevKeys, s.keys)
		targetID := filepath.Base(p)
		_ = w.logger.LogActivity(audit.ActivityInput{
			Actor:      "watcher",
			Action:     audit.ActionPolicyReload,
			TargetType: "policy_file",
			TargetID:   targetID,
			Reason:     "on-disk policy or list file changed",
			Diff:       diff,
			VersionTo:  fmt.Sprintf("gen=%d", gen),
		})
		if w.otel != nil {
			w.otel.RecordActivity(ctx, string(audit.ActionPolicyReload), "policy_file", "watcher", len(diff))
			w.otel.EmitGatewayEvent(gatewaylog.Event{
				Timestamp: time.Now().UTC(),
				EventType: gatewaylog.EventActivity,
				Severity:  gatewaylog.SeverityInfo,
				Activity: &gatewaylog.ActivityPayload{
					Actor:      "watcher",
					Action:     string(audit.ActionPolicyReload),
					TargetType: "policy_file",
					TargetID:   targetID,
					Reason:     "on-disk policy or list file changed",
					Diff:       activityDiffFromAudit(diff),
				},
			})
		}
		w.policyFileHashes[p] = s.hash
		w.policyListSnap[p] = s.keys
	}
}

func activityDiffFromAudit(in []audit.ActivityDiffEntry) []gatewaylog.DiffEntry {
	out := make([]gatewaylog.DiffEntry, 0, len(in))
	for _, d := range in {
		out = append(out, gatewaylog.DiffEntry{
			Path:   d.Path,
			Op:     d.Op,
			Before: d.Before,
			After:  d.After,
		})
	}
	return out
}

func diffPolicySnapshot(oldHash, newHash string, oldKeys, newKeys []string) []audit.ActivityDiffEntry {
	var diff []audit.ActivityDiffEntry
	diff = append(diff, audit.ActivityDiffEntry{
		Path:   "sha256",
		Op:     "replace",
		Before: oldHash,
		After:  newHash,
	})
	oldSet := map[string]struct{}{}
	for _, k := range oldKeys {
		oldSet[k] = struct{}{}
	}
	newSet := map[string]struct{}{}
	for _, k := range newKeys {
		newSet[k] = struct{}{}
	}
	for k := range newSet {
		if _, ok := oldSet[k]; !ok {
			diff = append(diff, audit.ActivityDiffEntry{Path: "rules[" + k + "]", Op: "add", After: k})
		}
	}
	for k := range oldSet {
		if _, ok := newSet[k]; !ok {
			diff = append(diff, audit.ActivityDiffEntry{Path: "rules[" + k + "]", Op: "remove", Before: k})
		}
	}
	return diff
}

func (w *InstallWatcher) policyWatchPaths() []string {
	var out []string
	if w.cfg.DataDir != "" {
		out = append(out,
			filepath.Join(w.cfg.DataDir, "block_list.yaml"),
			filepath.Join(w.cfg.DataDir, "allow_list.yaml"),
		)
	}
	if w.cfg.PolicyDir != "" {
		_ = filepath.Walk(w.cfg.PolicyDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml", ".json", ".rego":
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

func listKeysFromYAMLBytes(b []byte) []string {
	var rows []map[string]any
	if err := yaml.Unmarshal(b, &rows); err != nil || len(rows) == 0 {
		return nil
	}
	var keys []string
	for _, row := range rows {
		tt, _ := row["target_type"].(string)
		tn, _ := row["target_name"].(string)
		if tt != "" && tn != "" {
			keys = append(keys, tt+":"+tn)
		}
	}
	sort.Strings(keys)
	return keys
}
