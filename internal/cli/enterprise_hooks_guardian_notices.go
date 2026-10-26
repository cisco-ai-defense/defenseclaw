// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookGuardianNoticesFile records, in the guardian's data directory, the
// protected targets whose agent config the last standalone reconcile (Linux,
// macOS, Windows) found put back from a copy or recreated with DefenseClaw's
// hooks only (connector.AgentConfigStatus, GAP-0564, GAP-0588: a missing
// Hermes config.yaml lost the account's model and Bedrock settings while
// verify read ok). The enterprise status and verify warn about each. It is
// its own file: the guardian's state keeps the schema a prior binary reads
// strictly. Protected like the repair and restore records.
const hookGuardianNoticesFile = "hook_guardian_notices.json"

type enterpriseHookGuardianNotice struct {
	User      string `json:"user"`
	Connector string `json:"connector"`
	// AgentConfig is a connector.AgentConfigStatus code, never free text:
	// the per-user worker that reports it runs as the account.
	AgentConfig string `json:"agent_config"`
}

type enterpriseHookGuardianNoticeRecord struct {
	Version   int                            `json:"version"`
	UpdatedAt string                         `json:"updated_at"`
	Targets   []enterpriseHookGuardianNotice `json:"targets"`
}

// enterpriseHookAgentConfigNotice is the notice code the guardian records for
// a target that verified: the result's own (a Hermes or Devin config put back
// or recreated), else a Codex or Claude Code native OTLP exporter the managed
// install could not take back, which the account's take-back-pending marker
// records (connector.NativeOTLPTakeBackPending, GAP-1839, GAP-1840). The
// exporter fails no verify: the managed gateway never serves its credential,
// which the take-back revoked, and the next install or repair retries it.
func enterpriseHookAgentConfigNotice(result enterprisehooks.InstallResult) string {
	if result.AgentConfig != "" {
		return result.AgentConfig
	}
	if connector.NativeOTLPTakeBackPending(result.DataDir, result.Connector) {
		return connector.AgentConfigNativeOTLPTakeBackPending
	}
	return ""
}

// writeEnterpriseHookGuardianNotices replaces the record with this pass's
// notices. A pass with none removes it; an unchanged set is not rewritten.
// It is best effort: only status and verify read it.
func writeEnterpriseHookGuardianNotices(stderr io.Writer, dataDir string, notices []enterpriseHookGuardianNotice) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, hookGuardianNoticesFile)
	kept := notices[:0:0]
	for _, notice := range notices {
		if notice.AgentConfig != "" && connector.ValidAgentConfigStatus(notice.AgentConfig) {
			kept = append(kept, notice)
		}
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "[hook-guardian] warn: remove the agent config notices %s: %v\n", path, err)
		}
		return
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].User != kept[j].User {
			return kept[i].User < kept[j].User
		}
		return kept[i].Connector < kept[j].Connector
	})
	targets, _ := json.Marshal(kept)
	if previous, err := os.ReadFile(path); err == nil {
		var record enterpriseHookGuardianNoticeRecord
		if json.Unmarshal(previous, &record) == nil {
			if again, err := json.Marshal(record.Targets); err == nil && bytes.Equal(again, targets) {
				return
			}
		}
	}
	data, err := json.Marshal(enterpriseHookGuardianNoticeRecord{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Targets: kept})
	if err == nil {
		err = writeEnterpriseHookProtectedFile(path, append(data, '\n'))
	}
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] warn: record the agent config notices in %s: %v\n", path, err)
	}
}

// readEnterpriseHookGuardianNotices reads the record's notices with a code
// the guardian writes; nil without a readable record.
func readEnterpriseHookGuardianNotices(dataDir string) []enterpriseHookGuardianNotice {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	path := filepath.Join(dataDir, hookGuardianNoticesFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	data, err := readEnterpriseHookBoundedFile(path, info, hookGuardianRestoresMaxBytes, "hook guardian agent config notices")
	if err != nil {
		return nil
	}
	var record enterpriseHookGuardianNoticeRecord
	if json.Unmarshal(data, &record) != nil || record.Version != 1 {
		return nil
	}
	var out []enterpriseHookGuardianNotice
	for _, notice := range record.Targets {
		if notice.AgentConfig != "" && connector.ValidAgentConfigStatus(notice.AgentConfig) {
			out = append(out, notice)
		}
	}
	return out
}

// enterpriseHookGuardianNoticeMessages words the record's notices for the
// Windows status and verify (warning agent_settings_not_restored), one per
// account and connector, sorted; Linux and macOS word the same record in
// enterpriseunix. Names are bounded and plain: the per-user side may have
// chosen them.
func enterpriseHookGuardianNoticeMessages(dataDir string) []string {
	var out []string
	for _, notice := range readEnterpriseHookGuardianNotices(dataDir) {
		if message, ok := connector.AgentConfigNotice(notice.Connector, enterpriseHookNoticeName(notice.User), notice.AgentConfig); ok {
			out = append(out, message)
		}
	}
	sort.Strings(out)
	return out
}

// enterpriseHookNoticeName is an account name as a notice line shows it:
// printable, at most 128 bytes.
func enterpriseHookNoticeName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if len(name) > 128 {
		name = name[:128] + "..."
	}
	return name
}
