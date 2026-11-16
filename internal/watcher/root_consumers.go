package watcher

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rootConsumersOf is every connector that loads the watched root holding the
// skill or plugin event, owner first. A root several connectors load (an
// explicit gateway.watcher folder, or a shared layout) has one event owner,
// but each of its consumers loads what lands there, so each consumer has its
// connector-scoped asset rules applied to it. Only the innermost watched root
// holding the event counts: a root nested inside another watched root owns
// what lands in it, so the outer root consumers never load it as their own.
// Connectors that do not load the root are never in the list, so their scoped
// rules do not reach it. The Secure Client profile keeps the owner alone.
func (w *InstallWatcher) rootConsumersOf(evt InstallEvent, owner string) []string {
	out := []string{owner}
	if evt.Type != InstallSkill && evt.Type != InstallPlugin || len(w.rootConsumers) == 0 || strings.TrimSpace(evt.Path) == "" || w.secureClientActive() {
		return out
	}
	path := w.rootCoveragePath(evt.Path)
	prefix := string(evt.Type) + "\x00"
	var innermost string
	var connectors []string
	for key, loaded := range w.rootConsumers {
		root, ok := strings.CutPrefix(key, prefix)
		if !ok || !pathWithinRoot(path, root) {
			continue
		}
		if connectors == nil || len(root) > len(innermost) {
			innermost, connectors = root, loaded
		}
	}
	for _, connector := range connectors {
		if !containsFold(out, connector) {
			out = append(out, connector)
		}
	}
	return out
}

func containsFold(list []string, name string) bool {
	for _, item := range list {
		if strings.EqualFold(item, name) {
			return true
		}
	}
	return false
}

// rootAssetPolicy is evaluateRootAssetPolicy for the asset-policy input the
// watcher builds for evt.
func (w *InstallWatcher) rootAssetPolicy(cfg *config.Config, evt InstallEvent, owner string) (config.AssetPolicyDecision, string, []string) {
	return w.evaluateRootAssetPolicy(cfg, evt, owner, func(c string) config.AssetPolicyInput {
		return w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
			TargetType:     string(evt.Type),
			Name:           evt.Name,
			DeclaredNames:  declaredAssetNames(cfg, evt),
			Connector:      c,
			SourcePath:     evt.Path,
			RuntimeSurface: "watcher",
		})
	})
}

// evaluateRootAssetPolicy is the asset-policy decision for an install event
// across every connector that loads its root: the first connector whose rules
// block it, else the first whose rules would block it (observe mode), else
// the owner decision. It returns the connector the decision belongs to and
// every connector whose rules enforce a block of it, owner first: a copy that
// stays in its folder after a failed quarantine is loadable by each of them,
// so each needs the hold.
func (w *InstallWatcher) evaluateRootAssetPolicy(cfg *config.Config, evt InstallEvent, owner string, input func(connector string) config.AssetPolicyInput) (config.AssetPolicyDecision, string, []string) {
	best := cfg.EvaluateAssetPolicy(input(owner))
	bestConnector, bestRank := owner, assetBlockRank(best)
	var denying []string
	if bestRank == 2 {
		denying = append(denying, owner)
	}
	for _, connector := range w.rootConsumersOf(evt, owner)[1:] {
		decision := cfg.EvaluateAssetPolicy(input(connector))
		rank := assetBlockRank(decision)
		if rank == 2 {
			denying = append(denying, connector)
		}
		if rank > bestRank {
			best, bestConnector, bestRank = decision, connector, rank
		}
	}
	return best, bestConnector, denying
}

// assetBlockRank is 2 for an enforced block, 1 for one that only would
// block, 0 otherwise.
func assetBlockRank(d config.AssetPolicyDecision) int {
	switch {
	case d.Enabled && d.RawAction == "block" && d.Action == "block":
		return 2
	case d.Enabled && d.RawAction == "block":
		return 1
	}
	return 0
}
