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

package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/integrity"
)

func trustLevelRecordsWarning(level string) bool {
	l := strings.ToLower(strings.TrimSpace(level))
	return l == "clean_warning" || l == "allow_list"
}

func trustLevelRecordsAllowList(level string) bool {
	return strings.ToLower(strings.TrimSpace(level)) == "allow_list"
}

func (w *InstallWatcher) verdictEligibleForBaseline(v Verdict) bool {
	lvl := w.cfg.Integrity.TrustLevel
	switch v {
	case VerdictClean:
		return true
	case VerdictWarning:
		return trustLevelRecordsWarning(lvl)
	case VerdictAllowed:
		return trustLevelRecordsAllowList(lvl)
	default:
		return false
	}
}

func (w *InstallWatcher) integrityEnabledForType(t InstallType) bool {
	if !w.cfg.Integrity.Enabled {
		return false
	}
	switch t {
	case InstallSkill:
		return w.cfg.Integrity.Skill
	case InstallPlugin:
		return w.cfg.Integrity.Plugin
	default:
		return false
	}
}

func (w *InstallWatcher) loadIntegrityBaselinesFromStore() error {
	list, err := w.store.ListIntegrityBaselines()
	if err != nil {
		return err
	}
	for i := range list {
		b := list[i]
		if b.RootPath == "" {
			continue
		}
		if b.TargetType != "skill" && b.TargetType != "plugin" {
			continue
		}
		root := filepath.Clean(b.RootPath)
		copy := b
		w.baselineByRoot[root] = &copy
	}
	return nil
}

func (w *InstallWatcher) rememberBaselineRow(b *audit.IntegrityBaseline) {
	if b == nil || b.RootPath == "" {
		return
	}
	root := filepath.Clean(b.RootPath)
	copy := *b
	w.baselineByRoot[root] = &copy
}

func (w *InstallWatcher) postInstallIntegrity(ctx context.Context, evt InstallEvent, result AdmissionResult) {
	_ = ctx
	if !w.integrityEnabledForType(evt.Type) {
		return
	}
	if !w.verdictEligibleForBaseline(result.Verdict) {
		return
	}
	absPath, err := filepath.Abs(evt.Path)
	if err != nil {
		return
	}
	fp, nFiles, err := integrity.FingerprintDir(absPath)
	if err != nil {
		_ = w.logger.LogAction("integrity-baseline-skip", evt.Path,
			fmt.Sprintf("type=%s name=%s err=%v", evt.Type, evt.Name, err))
		return
	}
	meta, _ := json.Marshal(map[string]any{"file_count": nFiles})
	targetType := string(evt.Type)
	if err := w.store.UpsertIntegrityBaseline(targetType, evt.Name, absPath, fp, string(meta)); err != nil {
		_ = w.logger.LogAction("integrity-baseline-error", evt.Name, err.Error())
		return
	}
	row, err := w.store.GetIntegrityBaseline(targetType, evt.Name)
	if err != nil || row == nil {
		return
	}
	w.rememberBaselineRow(row)
	if w.fsw != nil {
		if err := w.ensureTreeWatched(w.fsw, absPath); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] integrity: watch tree %s: %v\n", absPath, err)
		}
	}
	_ = w.logger.LogAction("integrity-baseline", absPath,
		fmt.Sprintf("type=%s name=%s files=%d", targetType, evt.Name, nFiles))
}

func (w *InstallWatcher) ensureTreeWatched(fsw *fsnotify.Watcher, root string) error {
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		if w.watchedIntDirs[path] {
			return nil
		}
		if err := fsw.Add(path); err != nil {
			return err
		}
		w.watchedIntDirs[path] = true
		return nil
	})
}

func (w *InstallWatcher) integrityRootForPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	for root := range w.baselineByRoot {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if abs == r {
			return r
		}
		rel, err := filepath.Rel(r, abs)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return r
		}
	}
	return ""
}

func (w *InstallWatcher) handleIntegrityFilesystemEvent(ctx context.Context, event fsnotify.Event) {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
		return
	}
	root := w.integrityRootForPath(event.Name)
	if root == "" {
		return
	}
	if event.Op&fsnotify.Create != 0 {
		if fi, err := os.Stat(event.Name); err == nil && fi.IsDir() {
			_ = w.ensureTreeWatched(w.fsw, event.Name)
		}
	}
	w.mu.Lock()
	if _, ok := w.integrityPending[root]; !ok {
		w.integrityPending[root] = time.Now()
	}
	w.mu.Unlock()
}

func (w *InstallWatcher) flushIntegrityDrift(ctx context.Context) {
	if !w.cfg.Integrity.Enabled {
		return
	}
	w.mu.Lock()
	now := time.Now()
	var roots []string
	for root, first := range w.integrityPending {
		if now.Sub(first) >= w.debounce {
			roots = append(roots, root)
			delete(w.integrityPending, root)
		}
	}
	w.mu.Unlock()

	for _, root := range roots {
		w.runIntegrityDriftCheck(ctx, root)
	}
}

func (w *InstallWatcher) driftCooldownKey(b *audit.IntegrityBaseline) string {
	return b.TargetType + ":" + b.TargetName
}

func (w *InstallWatcher) shouldLogDrift(key string) bool {
	cool := w.cfg.Integrity.DriftLogCooldownS
	if cool <= 0 {
		cool = 120
	}
	last, ok := w.lastDriftLog[key]
	if ok && time.Since(last) < time.Duration(cool)*time.Second {
		return false
	}
	w.lastDriftLog[key] = time.Now()
	return true
}

func (w *InstallWatcher) runIntegrityDriftCheck(ctx context.Context, root string) {
	_ = ctx
	b, ok := w.baselineByRoot[filepath.Clean(root)]
	if !ok || b == nil {
		return
	}
	fp, nFiles, err := integrity.FingerprintDir(b.RootPath)
	if err != nil {
		_ = w.logger.LogAction("integrity-check-error", b.RootPath, err.Error())
		return
	}
	if fp == b.Fingerprint {
		return
	}
	key := w.driftCooldownKey(b)
	if !w.shouldLogDrift(key) {
		return
	}
	details := fmt.Sprintf("type=%s name=%s root=%s stored_fp=%s… current_fp=%s… files=%d reason=content_changed",
		b.TargetType, b.TargetName, b.RootPath, trimHex(b.Fingerprint), trimHex(fp), nFiles)
	target := fmt.Sprintf("%s:%s", b.TargetType, b.TargetName)
	if err := w.logger.LogIntegrityDrift(target, details); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] integrity drift log: %v\n", err)
	}

	onDrift := strings.ToLower(strings.TrimSpace(w.cfg.Integrity.OnDrift))
	if onDrift == "block" {
		w.applyIntegrityDriftBlock(b)
	}
}

func trimHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func (w *InstallWatcher) applyIntegrityDriftBlock(b *audit.IntegrityBaseline) {
	pe := enforce.NewPolicyEngine(w.store)
	tname := b.TargetName
	tt := b.TargetType
	reason := "integrity drift — filesystem changed after baseline"

	var installType InstallType
	switch tt {
	case "skill":
		installType = InstallSkill
	case "plugin":
		installType = InstallPlugin
	default:
		return
	}

	evt := InstallEvent{Type: installType, Name: tname, Path: b.RootPath, Timestamp: time.Now().UTC()}

	if w.takeActionFor(evt) {
		_ = pe.Block(tt, tname, reason)
		pe.SetSourcePath(tt, tname, b.RootPath)
		_ = w.logger.LogActionWithEnforcement("integrity-drift-block", tname,
			fmt.Sprintf("type=%s path=%s", tt, b.RootPath), map[string]string{
				"source_path": b.RootPath,
				"install":     "block",
			})
		w.enforceBlock(evt)
		if w.onIntegrityDrift != nil {
			w.onIntegrityDrift(tt, tname, b.RootPath, reason)
		}
	}
}
