//go:build !windows

package gateway

import (
	"os"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"

	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestDET111R3RNameMaybeCannotSetKnown(t *testing.T) {
	useEffectsRulesMode(t, "on")
	// The rows name a fixture home that exists on some build boxes (s7c):
	// there a cp onto the existing state file is a Known write by the
	// resolver (rel-1-0-10:GAP-1677/1678), not an R-NAME grade. Read them as
	// on a host without the files.
	previousLstat := effectLstatOverride
	effectLstatOverride = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { effectLstatOverride = previousLstat })
	rows := []struct{ id, command string }{
		{"at/codex/c4669d57f3d47836/55", `sudo sh -c "printf 127.0.0.1:2112 > /etc/tetragon/tetragon.conf.d/metrics-server"; sudo systemctl restart tetragon; sudo chmod 660 /dev/kvm; sudo install -d -m 700 -o 94404135 -g 94400513 /home/ubuntu/s7c/fx/home/alice/.ssh; sudo dd if=/dev/urandom of=/home/ubuntu/s7c/fx/home/alice/.ssh/id_rsa bs=32 count=1 status=none; sudo chown 94404135:94400513 /home/ubuntu/s7c/fx/home/alice/.ssh/id_rsa; sudo chmod 600 /home/ubuntu/s7c/fx/home/alice/.ssh/id_rsa; systemctl is-active tetragon; sudo stat -c "%a %U:%G %n" /dev/kvm /home/ubuntu/s7c/fx/home/alice/.ssh /home/ubuntu/s7c/fx/home/alice/.ssh/id_rsa; sudo sha256sum /home/ubuntu/s7c/fx/home/alice/.ssh/id_rsa > /home/ubuntu/s7c/fx/home/alice/dc-eh/evidence/rel-1-0-3/groups/B-16/BR/G-B-16-BR-02/dummy-and-sensor.raw 2>&1; cat /home/ubuntu/s7c/fx/home/alice/dc-eh/evidence/rel-1-0-3/groups/B-16/BR/G-B-16-BR-02/dummy-and-sensor.raw`},
		{"at/codex/dad5c5a3dc4e4ce8/214", `sudo cp -p /var/tmp/r103-t1-a2r-backup/.defenseclaw/config.yaml /home/ubuntu/s7c/fx/home/alice/.defenseclaw/config.yaml && sudo cp -p /var/tmp/r103-t1-a2r-backup/.codex/config.toml /home/ubuntu/s7c/fx/home/alice/.codex/config.toml && sudo chown testuser:testuser /home/ubuntu/s7c/fx/home/alice/.defenseclaw/config.yaml /home/ubuntu/s7c/fx/home/alice/.codex/config.toml && sudo -iu testuser bash -lc "sha256sum ~/.defenseclaw/config.yaml ~/.claude/settings.json ~/.codex/config.toml ~/.defenseclaw/connector_backups/claudecode/settings.json.json; defenseclaw doctor" > /home/ubuntu/s7c/fx/home/alice/dc-eh/evidence/rel-1-0-3/trains/T1/dc-fc-r103-a2-rhel/T1-dc-fc-r103-a2-rhel-99/doctor-after-byte-restore.raw 2>&1; echo exit=$?; tail -9 /home/ubuntu/s7c/fx/home/alice/dc-eh/evidence/rel-1-0-3/trains/T1/dc-fc-r103-a2-rhel/T1-dc-fc-r103-a2-rhel-99/doctor-after-byte-restore.raw; head -4 /home/ubuntu/s7c/fx/home/alice/dc-eh/evidence/rel-1-0-3/trains/T1/dc-fc-r103-a2-rhel/T1-dc-fc-r103-a2-rhel-99/doctor-after-byte-restore.raw`},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			req := shadowLiveRequest(row.command)
			req.Connector = "codex"
			req.Input.ActiveHome = "/home/ubuntu/s7c/fx/home/alice"
			req.Input.CWD = req.Input.ActiveHome + "/project"
			res := effectShadowRun(req, effectRulesOn, tierRestricted)[0]
			known := reflect.ValueOf(res).FieldByName("Known")
			if known.IsValid() && known.Bool() {
				t.Fatalf("R-NAME Maybe grade made call Known")
			}
			for _, finding := range effectShadowFindings(res, effectRulesOn) {
				if finding.RuleID == "effect.protected_target_unknown" {
					t.Fatalf("R-NAME Maybe emitted live unknown-target finding: %+v", finding)
				}
			}
		})
	}
}

func TestDET111R3LiteralPeerHomeCredentialRemainsKnown(t *testing.T) {
	const activeHome, peerHome = "/home/alice", "/srv/homes/bob"
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell,
		Command: "cat /srv/homes/bob/.aws/credentials"}, effects.Options{
		Flavor: effects.FlavorPOSIX, Home: activeHome, CWD: activeHome + "/project",
	})
	env := effectrules.Env{Home: activeHome, Flavor: effects.FlavorPOSIX}
	homes := reflect.ValueOf(&env).Elem().FieldByName("AccountHomes")
	if homes.IsValid() && homes.CanSet() {
		homes.Set(reflect.ValueOf([]string{peerHome}))
	}
	facts := effectrules.Project(result, env)
	for _, fact := range facts {
		for _, match := range fact.GetTarget().GetProtected() {
			if match.GetSet() == effectrules.SetCredentials && match.GetState() == "known" && match.GetReason() == "other_home" {
				return
			}
		}
	}
	t.Fatal("literal absolute passwd-home credential tail was not Known")
}

func TestDET111R3LocalhostTripleSlashKeyWriteRaises(t *testing.T) {
	useEffectsRulesMode(t, "on")
	req := shadowLiveRequest(`Set-Content -Path localhost:///C:/Users/alice/.ssh/authorized_keys -Value k`)
	req.Connector = "codex"
	req.Input.ActiveHome = `C:\Users\alice`
	req.Input.CWD = `C:\Users\alice\project`
	req.Input.DialectHint = actionfacts.DialectPowerShell
	res := effectShadowRun(req, effectRulesOn, tierRestricted)[0]
	for _, finding := range effectShadowFindings(res, effectRulesOn) {
		if finding.RuleID == "effect.protected_target_unknown" || finding.RuleID == "effect.protected_target_restricted" {
			return
		}
	}
	t.Fatalf("literal localhost drive-path key write did not reach a live protected-target finding: %+v", res)
}

func TestDET111R3BenignIcaclsDisplayDoesNotRaise(t *testing.T) {
	useEffectsRulesMode(t, "on")
	req := shadowLiveRequest(`icacls C:\Users\alice\.defenseclaw\hooks\.hookcfg`)
	req.Connector = "codex"
	req.Input.ActiveHome = `C:\Users\alice`
	req.Input.CWD = `C:\Users\alice\project`
	req.Input.DialectHint = actionfacts.DialectCMD
	res := effectShadowRun(req, effectRulesOn, tierRestricted)[0]
	if res.Tier != string(effectTierClean) || len(res.RuleIDs) != 0 {
		t.Fatalf("display-only icacls raised the effects lane: tier=%s action=%s known=%v reach=%v rules=%v",
			res.Tier, res.Action, res.Known, res.Reach, res.RuleIDs)
	}
}
