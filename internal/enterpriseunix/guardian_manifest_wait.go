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

// awaitGuardianReconcile lets verify, run right after the enumerator changed
// the manifest or right after an enrolled account was deleted, wait for the
// guardian to catch up instead of failing on the seconds between the two:
//   - until the guardian activation names the current manifest bytes (verify
//     right after a fresh pkg install exited 1 with "live registration check
//     did not prove the current managed Hermes target" and passed 20 s later,
//     GAP-2176; the same window follows the enumerator revoking a deleted
//     account's target), and
//   - until the guardian state records the removal of every enabled target
//     whose account the directory confirms gone, so the delete never shows as
//     a failed verify between the account going and the guardian noticing
//     (GAP-0777).
//
// The guardian reconciles each minute, so one deadline, GuardianReconcileTimeout,
// covers one reconcile with margin; each poll re-reads the manifest, so a
// target the enumerator dropped meanwhile is no longer waited for. A guardian
// that does not catch up in time is named; the checks below still run and keep
// their verdicts, so a guardian that truly fails to reconcile still fails
// verify.
func (l *lifecycle) awaitGuardianReconcile(ctx context.Context) {
	env := l.env
	asked := map[string]bool{}
	pending := func() (manifestPending bool, unrecorded []string) {
		return l.guardianActivationNamesOtherManifest(), l.guardianRetireUnrecorded(l.guardianGoneTargets(asked))
	}
	manifestPending, unrecorded := pending()
	if !manifestPending && len(unrecorded) == 0 {
		return
	}
	deadline := env.Now().Add(env.GuardianReconcileTimeout)
	for manifestPending || len(unrecorded) > 0 {
		if !env.Now().Before(deadline) {
			if manifestPending {
				l.result.AddWarning(codeGuardianReportPending, fmt.Sprintf(
					"the hook guardian has not reconciled the current enrollment manifest within %s, so the newest enrolled targets are not proven yet; run `%s` again in a minute",
					env.GuardianReconcileTimeout, env.lifecycleCommand(ActionVerify)))
			}
			if len(unrecorded) > 0 {
				l.result.AddWarning(codeGuardianReportPending, fmt.Sprintf(
					"the hook guardian has not recorded the removal of %s within %s; the account is gone, so run `%s` again in a minute",
					strings.Join(unrecorded, ", "), env.GuardianReconcileTimeout, env.lifecycleCommand(ActionVerify)))
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(env.PollInterval):
		}
		manifestPending, unrecorded = pending()
	}
}

// goneTarget is an enabled manifest target whose account the directory
// confirms gone, with the uid the manifest enrolled it under.
type goneTarget struct {
	user, connector string
	uid             int
}

// guardianGoneTargets are the enabled manifest targets whose account the
// directory confirms gone (guardianAccountConfirmedGone, the evidence the
// guardian retires on). Each account is asked once per asked map. A missing
// manifest names nothing.
func (l *lifecycle) guardianGoneTargets(asked map[string]bool) []goneTarget {
	env := l.env
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		return nil
	}
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
			gone = append(gone, goneTarget{user: user, connector: strings.TrimSpace(target.Connector), uid: uid})
		}
	}
	return gone
}

// guardianRetireUnrecorded are the gone targets the guardian state has no
// row for that says so. A row counts only for the account it was recorded
// for: the same name and connector, and the same uid when the manifest
// enrolled one, so the removal of an earlier account of that name is no
// proof for a new account that took it over. In that window the guardian
// still reports the target protected, so verify, which cannot excuse a
// removal the guardian has not recorded, failed on the seconds between the
// delete and the guardian next reconcile (GAP-0777). An unreadable state
// records nothing.
func (l *lifecycle) guardianRetireUnrecorded(gone []goneTarget) []string {
	env := l.env
	var state struct {
		Results []struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
			UID       int    `json:"uid"`
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
			if target.uid > 0 && row.UID != target.uid {
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
