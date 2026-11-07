//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// guardianActivationNamesOtherManifest reports whether the guardian's
// activation receipt exists and names manifest bytes other than the current
// manifest: the enumerator rewrote the manifest (a fresh install enrolls
// every eligible account, a new account is enrolled) and the guardian has
// not reconciled it yet. A missing manifest or receipt is not a pending
// reconcile; those keep their own verdicts.
func (l *lifecycle) guardianActivationNamesOtherManifest() bool {
	env := l.env
	manifest, err := readBounded(env.P(env.Layout.ManifestPath), maxInputBytes)
	if err != nil {
		return false
	}
	data, err := readBounded(env.P(filepath.Join(env.Layout.GuardianAuthDir, guardianActivationFile)), 4<<20)
	if err != nil {
		return false
	}
	var activation struct {
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if json.Unmarshal(data, &activation) != nil || activation.ManifestSHA256 == "" {
		return false
	}
	digest := sha256.Sum256(manifest)
	return activation.ManifestSHA256 != hex.EncodeToString(digest[:])
}

// awaitGuardianManifestReconcile lets verify, run right after the enumerator
// changed the manifest, wait (bounded by GuardianReportTimeout) for the
// guardian's reconcile of it instead of failing on the seconds between the
// two: verify right after a fresh pkg install exited 1 with "live
// registration check did not prove the current managed Hermes target" and
// passed 20 s later (GAP-2176). A reconcile that does not come in time is
// named; the checks below still run and keep their verdicts.
func (l *lifecycle) awaitGuardianManifestReconcile(ctx context.Context) {
	env := l.env
	if !l.guardianActivationNamesOtherManifest() {
		return
	}
	deadline := env.Now().Add(env.GuardianReportTimeout)
	for l.guardianActivationNamesOtherManifest() {
		if !env.Now().Before(deadline) {
			l.result.AddWarning(codeGuardianReportPending, fmt.Sprintf(
				"the hook guardian has not reconciled the current enrollment manifest within %s, so the newest enrolled targets are not proven yet; run `%s` again in a minute",
				env.GuardianReportTimeout, env.lifecycleCommand(ActionVerify)))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(env.PollInterval):
		}
	}
}

// goneTarget is a manifest target whose account the directory confirms gone.
type goneTarget struct{ user, connector string }

// guardianGoneTargets are the enabled manifest targets whose account the
// directory confirms gone (guardianAccountConfirmedGone, the evidence the
// guardian retires on). Each account is asked once. A missing manifest names
// nothing.
func (l *lifecycle) guardianGoneTargets() []goneTarget {
	env := l.env
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		return nil
	}
	asked := map[string]bool{}
	var gone []goneTarget
	for _, target := range manifest.Targets {
		user := strings.TrimSpace(target.User)
		if !target.IsEnabled() || user == "" {
			continue
		}
		uid := 0
		if target.UID != nil {
			uid = *target.UID
		}
		key := fmt.Sprintf("%s:%d", user, uid)
		if _, ok := asked[key]; !ok {
			asked[key] = guardianAccountConfirmedGone(user, uid)
		}
		if asked[key] {
			gone = append(gone, goneTarget{user: user, connector: strings.TrimSpace(target.Connector)})
		}
	}
	return gone
}

// guardianRetireUnrecorded are the gone targets the guardian state has no
// row for that says so. In that window the guardian still reports the
// target protected, so verify, which cannot excuse a removal the guardian
// has not recorded, failed on the seconds between the delete and the
// guardian next reconcile (GAP-0777). An unreadable state records nothing.
func (l *lifecycle) guardianRetireUnrecorded(gone []goneTarget) []string {
	env := l.env
	var state struct {
		Results []struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Removed   bool   `json:"removed"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	var pending []string
	for _, target := range gone {
		recorded := false
		for _, row := range state.Results {
			if row.OK || !strings.EqualFold(row.User, target.user) || !strings.EqualFold(row.Connector, target.connector) {
				continue
			}
			if row.Removed || targetAccountMissingError(row.Error) || targetHomeUnavailableError(row.Error) {
				recorded = true
				break
			}
		}
		if !recorded {
			pending = append(pending, target.user)
		}
	}
	sort.Strings(pending)
	return slices.Compact(pending)
}

// awaitGuardianRetire lets verify, run just after an enrolled account was
// deleted, wait (bounded by GuardianRetireTimeout, the guardian reconciles
// each minute) for the guardian to record the target as retired before it
// judges the target, so the delete never shows as a failed verify between
// the account going and the guardian noticing. A guardian that does not
// record it in time is named; the checks keep their verdicts.
func (l *lifecycle) awaitGuardianRetire(ctx context.Context) {
	env := l.env
	gone := l.guardianGoneTargets()
	pending := l.guardianRetireUnrecorded(gone)
	if len(pending) == 0 {
		return
	}
	deadline := env.Now().Add(env.GuardianRetireTimeout)
	for len(pending) > 0 {
		if !env.Now().Before(deadline) {
			l.result.AddWarning(codeGuardianReportPending, fmt.Sprintf(
				"the hook guardian has not recorded the removal of %s within %s; the account is gone, so run `%s` again in a minute",
				strings.Join(pending, ", "), env.GuardianRetireTimeout, env.lifecycleCommand(ActionVerify)))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(env.PollInterval):
		}
		pending = l.guardianRetireUnrecorded(gone)
	}
}
