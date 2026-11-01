//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
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
