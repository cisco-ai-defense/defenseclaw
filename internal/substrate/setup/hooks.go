// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SubstrateAPI is the part of the Agent Substrate control API the hook
// steps use. The CLI adapts the ateapi client to it; tests use a fake.
// Not-found is (nil, nil) for the getters.
type SubstrateAPI interface {
	GetAtespace(ctx context.Context, name string) (bool, error)
	CreateAtespace(ctx context.Context, name string) error
	// GetAccessPolicy returns the atespace's policy, or the global one for
	// atespace "".
	GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error)
	// PutAccessPolicy creates the policy when UID is empty and updates it
	// (with the UID and version preconditions) otherwise.
	PutAccessPolicy(ctx context.Context, p AccessPolicy) error
	// ListActors lists the actors of atespace, every atespace for "".
	ListActors(ctx context.Context, atespace string) ([]ActorRef, error)
	GetEgressPolicy(ctx context.Context, actor ActorRef) (*EgressPolicy, error)
	DeleteEgressPolicy(ctx context.Context, actor ActorRef) error
}

// ActorRef names an actor.
type ActorRef struct {
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
}

func (r ActorRef) String() string { return r.Atespace + "/" + r.Name }

// EgressPolicy is what the uninstall needs of an actor's egress policy: the
// hostnames of its rules.
type EgressPolicy struct {
	Actor     ActorRef
	Hostnames []string
}

// IsDefenseClaws reports whether p was rendered by DefenseClaw: every
// DefenseClaw policy has the rule to the actor Service, and no other writer
// has a reason to name it.
func (p EgressPolicy) IsDefenseClaws(actorHost string) bool {
	short := strings.TrimSuffix(actorHost, ".cluster.local")
	for _, h := range p.Hostnames {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if hp, _, ok := strings.Cut(h, ":"); ok {
			h = hp
		}
		if h == actorHost || h == short || h == short+".cluster.local" {
			return true
		}
	}
	return false
}

// ConfigMap is a Kubernetes ConfigMap's identity and data.
type ConfigMap struct {
	Namespace       string
	Name            string
	ResourceVersion string
	Data            map[string]string
	// Annotations and Labels are carried through an update, so a write keeps
	// what other tools (and GrantedUserSecretsAnnotation) recorded on the
	// object (GAP-0909 added the labels: the PUT replaces the whole object).
	Annotations map[string]string
	Labels      map[string]string
}

// GrantedUserSecretsAnnotation records, on the credential provider policy
// ConfigMap, the self-service namespace setup last granted to the launcher
// atespaces. When self_service_secrets.namespace changes, the recorded one
// is revoked (RV3 P3-4). Setup does not delete the orphan values in the old
// namespace (that would widen the hook Jobs' access); it prints the kubectl
// delete command. A namespace renamed in the same upgrade that first writes
// this annotation is not caught: the first run only records it.
const GrantedUserSecretsAnnotation = "defenseclaw.cisco.com/granted-user-secrets-namespace"

// KubeAPI is the part of the Kubernetes API the hook steps use. Not-found
// is (nil, nil) for GetConfigMap and nil for DeleteSecret.
type KubeAPI interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error)
	UpdateConfigMap(ctx context.Context, cm *ConfigMap) error
	// RestartDeployment rolls a Deployment (kubectl rollout restart).
	RestartDeployment(ctx context.Context, namespace, name string) error
	DeleteSecret(ctx context.Context, namespace, name string) error
	// ScaleDeployment sets a Deployment's replicas and returns the previous
	// count; found is false when the Deployment does not exist.
	ScaleDeployment(ctx context.Context, namespace, name string, replicas int32) (prev int32, found bool, err error)
	// DeploymentPods is the number of pods a Deployment still has,
	// terminating ones included (they can still write); 0 when it does not
	// exist.
	DeploymentPods(ctx context.Context, namespace, name string) (int32, error)
	// DeleteJob deletes a Job and, in the background, its pods; found is
	// false when it does not exist.
	DeleteJob(ctx context.Context, namespace, name string) (found bool, err error)
}

// LeftoverHookJobs are the chart's hook Jobs other than pre-delete
// (templates/hooks/jobs.yaml). A failed hook keeps its Job and Error pod
// (hook-delete-policy hook-succeeded; before-hook-creation only fires when
// the same hook runs again), so the pre-delete hook removes them, by name in
// the release namespace (GAP-0609). The chart's uninstall Role names the
// same list.
var LeftoverHookJobs = []string{"defenseclaw-chain-key", "defenseclaw-relay-session", "defenseclaw-pre-upgrade",
	"defenseclaw-pre-rollback", "defenseclaw-bootstrap"}

// StepReport is what a hook step did, for the Job log and `--json`.
type StepReport struct {
	Step     string         `json:"step"`
	Policies []PolicyChange `json:"policies,omitempty"`
	Grants   []GrantChange  `json:"grants,omitempty"`
	Removed  []string       `json:"removed_egress_policies,omitempty"`
	Notes    []string       `json:"notes,omitempty"`
}

func (r *StepReport) note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// Bootstrap writes DefenseClaw's OpenFGA grants with a global owner's
// client: it creates the launcher atespaces, gives each the launcher policy
// (only DefenseClaw edits), adds DefenseClaw as editor in the other writable
// atespaces and as global viewer, then grants the launcher atespaces the
// secrets namespace in the credential provider policy and restarts the
// provider so it reads the policy. It is idempotent.
//
// owner nil is an upgrade without the owner token Secret (the first
// bootstrap deleted it): the access policies stay as they are, but the
// credential provider grant, which needs only the Kubernetes API, still
// follows the plan. Before, that upgrade skipped the grant too, so a cluster
// upgraded to a chart with self-service secrets never granted their
// namespace and the provider refused every bound person secret (GAP-1076).
func Bootstrap(ctx context.Context, plan ChartPlan, owner SubstrateAPI, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "bootstrap"}
	if owner == nil {
		r.note("no owner token Secret: the access policies were not touched. Doctor checks them; " +
			"create the Secret again to rewrite them.")
		if plan.CredentialProvider.Grant {
			if err := grantProvider(ctx, plan, kube, &r); err != nil {
				return r, err
			}
		}
		return r, nil
	}
	for _, a := range plan.LauncherAtespaces {
		ok, err := owner.GetAtespace(ctx, a)
		if err != nil {
			return r, fmt.Errorf("atespace %s: %w", a, err)
		}
		if !ok {
			if err := owner.CreateAtespace(ctx, a); err != nil {
				return r, fmt.Errorf("create atespace %s: %w", a, err)
			}
			r.note("created launcher atespace %s", a)
		}
		cur, err := owner.GetAccessPolicy(ctx, a)
		if err != nil {
			return r, fmt.Errorf("access policy of %s: %w", a, err)
		}
		next, changes := LauncherPolicy(a, cur, plan.Editors)
		if err := putIfChanged(ctx, owner, next, changes, &r); err != nil {
			return r, err
		}
	}
	for _, a := range plan.WritableAtespaces {
		if slices.Contains(plan.LauncherAtespaces, a) {
			continue
		}
		ok, err := owner.GetAtespace(ctx, a)
		if err != nil {
			return r, fmt.Errorf("atespace %s: %w", a, err)
		}
		if !ok {
			// Managed atespaces belong to their teams: never create one.
			r.note("managed atespace %s does not exist yet; run the bootstrap again after it is created", a)
			continue
		}
		cur, err := owner.GetAccessPolicy(ctx, a)
		if err != nil {
			return r, fmt.Errorf("access policy of %s: %w", a, err)
		}
		next, changes := GrantPolicy(a, cur, RoleEditor, plan.Editors)
		if err := putIfChanged(ctx, owner, next, changes, &r); err != nil {
			return r, err
		}
	}
	cur, err := owner.GetAccessPolicy(ctx, "")
	if err != nil {
		return r, fmt.Errorf("global access policy: %w", err)
	}
	viewers := plan.GlobalViewers
	next, changes := GrantPolicy("", cur, RoleViewer, viewers)
	if err := putIfChanged(ctx, owner, next, changes, &r); err != nil {
		return r, err
	}
	if cur != nil {
		if n := len(cur.Members(RoleOwner)); n > 0 {
			r.note("the global policy lists %d owner member(s); every global owner can create atespaces "+
				"and edit launcher atespaces. Keep the list short (E3).", n)
		}
	}
	if plan.CredentialProvider.Grant {
		if err := grantProvider(ctx, plan, kube, &r); err != nil {
			return r, err
		}
	}
	if plan.DeleteOwnerToken && plan.OwnerTokenSecret != "" {
		if err := kube.DeleteSecret(ctx, plan.Namespace, plan.OwnerTokenSecret); err != nil {
			r.note("could not delete the owner token Secret %s: %v; delete it by hand", plan.OwnerTokenSecret, err)
		} else {
			r.note("deleted the owner token Secret %s", plan.OwnerTokenSecret)
		}
	}
	return r, nil
}

func putIfChanged(ctx context.Context, api SubstrateAPI, p AccessPolicy, changes []PolicyChange, r *StepReport) error {
	if len(changes) == 0 {
		return nil
	}
	if err := api.PutAccessPolicy(ctx, p); err != nil {
		scope := "the global access policy"
		if p.Atespace != "" {
			scope = "the access policy of " + p.Atespace
		}
		return fmt.Errorf("write %s: %w", scope, err)
	}
	r.Policies = append(r.Policies, changes...)
	return nil
}

func grantProvider(ctx context.Context, plan ChartPlan, kube KubeAPI, r *StepReport) error {
	cp := plan.CredentialProvider
	cm, err := kube.GetConfigMap(ctx, plan.SubstrateNamespace, cp.ConfigMap)
	if err != nil {
		return fmt.Errorf("credential provider policy: %w", err)
	}
	if cm == nil {
		r.note("the credential provider policy %s/%s does not exist: the Kubernetes credential provider is not installed, "+
			"so no grant was written", plan.SubstrateNamespace, cp.ConfigMap)
		return nil
	}
	grant, revoke := cp.grantedNamespaces()
	// The namespace granted by the last run is revoked when it changed or
	// self-service went off (RV3 P3-4).
	cur := ""
	if len(grant) > 1 {
		cur = grant[1]
	}
	prev := cm.Annotations[GrantedUserSecretsAnnotation]
	if prev != "" && prev != cur && prev != cp.SecretsNamespace && !slices.Contains(revoke, prev) {
		revoke = append(revoke, prev)
		if cur != "" {
			r.note("self-service secrets moved from namespace %s to %s: the grant of %s is revoked. "+
				"The values people set there (Secrets named dc-b-*) are no longer read; delete them with "+
				"`kubectl -n %s delete secret -l app.kubernetes.io/managed-by=defenseclaw` once nobody needs them",
				prev, cur, prev, prev)
		}
	}
	text := cm.Data[NamespacePolicyKey]
	var changes []GrantChange
	for _, ns := range grant {
		var granted, revoked []GrantChange
		var err error
		if text, granted, err = GrantNamespace(text, plan.LauncherAtespaces, ns); err != nil {
			return err
		}
		// An atespace that left launcher_atespaces loses the grant (GAP-0083).
		if text, revoked, err = RevokeNamespaceExcept(text, plan.LauncherAtespaces, ns); err != nil {
			return err
		}
		changes = append(append(changes, granted...), revoked...)
	}
	// Self-service secrets turned off: no atespace keeps their namespace.
	for _, ns := range revoke {
		var revoked []GrantChange
		var err error
		if text, revoked, err = RevokeNamespaceExcept(text, nil, ns); err != nil {
			return err
		}
		changes = append(changes, revoked...)
	}
	if len(changes) == 0 && prev == cur {
		return nil
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[NamespacePolicyKey] = text
	if cur == "" {
		delete(cm.Annotations, GrantedUserSecretsAnnotation)
	} else {
		if cm.Annotations == nil {
			cm.Annotations = map[string]string{}
		}
		cm.Annotations[GrantedUserSecretsAnnotation] = cur
	}
	if err := kube.UpdateConfigMap(ctx, cm); err != nil {
		return fmt.Errorf("credential provider policy: %w", err)
	}
	r.Grants = append(r.Grants, changes...)
	if len(changes) == 0 {
		return nil
	}
	if err := kube.RestartDeployment(ctx, plan.SubstrateNamespace, cp.Deployment); err != nil {
		return fmt.Errorf("restart the credential provider (it reads its policy at start only): %w", err)
	}
	r.note("restarted %s/%s to load the grant", plan.SubstrateNamespace, cp.Deployment)
	return nil
}

func storeState(ctx context.Context, plan ChartPlan, kube KubeAPI) (*StoreState, error) {
	cm, err := kube.GetConfigMap(ctx, plan.Namespace, plan.StoreStateConfigMap)
	if err != nil {
		return nil, fmt.Errorf("store state: %w", err)
	}
	if cm == nil {
		return nil, nil
	}
	return ParseStoreState(cm.Data)
}

// PreUpgrade checks the release about to roll out: its config validates,
// the upgrade does not skip a minor (N-1 -> N), and its gateway reads the
// store's schema. validate is the config validation the CLI passes in.
func PreUpgrade(ctx context.Context, plan ChartPlan, config []byte, validate func([]byte) error, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "pre-upgrade"}
	if validate != nil {
		if err := validate(config); err != nil {
			return r, fmt.Errorf("the new config.yaml is not valid, nothing was changed: %w", err)
		}
	}
	st, err := storeState(ctx, plan, kube)
	if err != nil {
		return r, err
	}
	if st != nil {
		if err := CheckUpgrade(st.WrittenByVersion, plan.AppVersion); err != nil {
			return r, err
		}
		if err := CheckRollback(plan.StoreSchema, st); err != nil {
			return r, err
		}
		if plan.StoreSchema > st.SchemaVersion {
			r.note("the leader migrates the store from schema %d to %d on start, after a backup", st.SchemaVersion, plan.StoreSchema)
		}
	}
	return r, nil
}

// PreRollback refuses a rollback to a release that reads an older store
// schema than the store has, naming the backup (E25), and how to clear the
// revision helm keeps for the refused rollback (GAP-0448). helm writes that
// revision before it runs the hook, so every refusal carries the recovery: a
// store state that cannot be read or parsed leaves it as much as a schema
// refusal does (GAP-0666).
func PreRollback(ctx context.Context, plan ChartPlan, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "pre-rollback"}
	cm, err := kube.GetConfigMap(ctx, plan.Namespace, plan.StoreStateConfigMap)
	if err != nil {
		return r, fmt.Errorf("store state: %w. %s", err, RefusedRollbackRecovery(plan))
	}
	var st *StoreState
	if cm != nil {
		if st, err = ParseStoreState(cm.Data); err != nil {
			// The same ConfigMap fails every rerun of this hook, so clearing
			// the pending-rollback revision with a helm rollback is not enough:
			// the ConfigMap is repaired first (GAP-0917).
			return r, fmt.Errorf("%w. %s", err, UnreadableStoreStateRecovery(plan))
		}
	}
	if err := CheckRollback(plan.StoreSchema, st); err != nil {
		return r, fmt.Errorf("%w. %s", err, RefusedRollbackRecovery(plan))
	}
	return r, nil
}

// RefusedRollbackRecovery says how to clear a refused rollback. helm
// writes the rollback revision (status pending-rollback) before it runs
// the pre-rollback hook and leaves it there when the hook fails, so every
// later helm upgrade fails with "another operation (install/upgrade/
// rollback) is in progress" (GAP-0448). A rollback to the revision that is
// deployed now is allowed over it (helm checks no pending state on a
// rollback), passes this check (that release reads the store's schema) and
// changes nothing; then upgrades work again.
func RefusedRollbackRecovery(plan ChartPlan) string {
	return fmt.Sprintf("Nothing was rolled back, but helm keeps this rollback as a pending-rollback revision and refuses "+
		"every helm upgrade until it is cleared: run helm -n %[1]s rollback %[2]s N, where N is the revision helm -n %[1]s "+
		"history %[2]s shows as deployed (it changes nothing), then upgrade as usual", plan.Namespace, plan.Release)
}

// UnreadableStoreStateRecovery is the recovery for a store-state ConfigMap
// that does not parse. Every rollback runs this hook again and fails the same
// way, so the ConfigMap comes first: set schema_version to the whole number the
// store is at (the leader logs it at start), or delete the ConfigMap (the
// recorded backup name is lost, the leader writes a new one at its next
// start). Then the pending-rollback revision is cleared as for any refusal.
func UnreadableStoreStateRecovery(plan ChartPlan) string {
	return fmt.Sprintf("Nothing was rolled back. Repairing the ConfigMap comes first, because a helm rollback runs this "+
		"check again and fails the same way: run kubectl -n %[1]s edit configmap %[3]s and set %[4]s to the schema version "+
		"the store is at (a whole number, 1 or more), or run kubectl -n %[1]s delete configmap %[3]s (the leader writes a "+
		"new one at its next start; the backup name it recorded is lost). Then clear the pending-rollback revision helm "+
		"keeps: run helm -n %[1]s rollback %[2]s N, where N is the revision helm -n %[1]s history %[2]s shows as deployed, "+
		"and retry the rollback you wanted", plan.Namespace, plan.Release, plan.StoreStateConfigMap, StoreStateSchemaKey)
}

// ErrPoliciesLeft fails the uninstall while DefenseClaw-written egress
// policies remain: without DefenseClaw their hosts would stay open.
var ErrPoliciesLeft = errors.New("DefenseClaw egress policies remain")

// Uninstall timing: how long PreDelete waits for the controller's pods to
// stop, and how long after the sweep it looks again. The recheck covers a
// write the controller had in flight when it stopped (it polls every 2 s).
var (
	ControllerStopTimeout = 2 * time.Minute
	RecheckAfter          = 5 * time.Second
	pollEvery             = time.Second
)

// PreDelete first stops the controller (it would recreate every policy on
// its next poll), then removes every egress policy DefenseClaw wrote, so
// actors fall back to Substrate's default deny, looks again after
// RecheckAfter, and revokes every credential provider grant of the secrets
// namespace. It fails while any DefenseClaw policy remains, which stops
// `helm uninstall`; the controller is then scaled back so the policies
// that remain stay enforced (GAP-0056).
func PreDelete(ctx context.Context, plan ChartPlan, api SubstrateAPI, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "pre-delete"}
	prev, stopped, err := stopController(ctx, plan, kube, &r)
	if err != nil {
		// stopController has put the controller back (or says it could not).
		return r, fmt.Errorf("stop the controller before removing policies (it would write them again): %w", err)
	}
	// restore ends a failed uninstall with the controller running again, so
	// the policies that remain stay enforced; a failed scale-back is part of
	// the error, never only a note (GAP-0056).
	restore := func(cause error) error {
		if !stopped {
			return cause
		}
		return scaleBack(ctx, plan, kube, prev, &r, cause)
	}
	left, err := sweepPolicies(ctx, plan, api, &r)
	if err == nil && len(left) == 0 {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(RecheckAfter):
			before := len(r.Removed)
			left, err = sweepPolicies(ctx, plan, api, &r)
			if n := len(r.Removed) - before; n > 0 {
				r.note("%d DefenseClaw policies came back after the first sweep and were removed again", n)
			}
		}
	}
	if err != nil {
		return r, restore(err)
	}
	if plan.CredentialProvider.Grant {
		if err := revokeProvider(ctx, plan, kube, &r); err != nil {
			r.note("the credential provider grant stays: %v", err)
		}
	}
	if plan.AuthDelegatorBinding != "" {
		r.note("helm removes the cluster-wide ClusterRoleBinding %s (gateway ServiceAccount to system:auth-delegator, "+
			"for the Kubernetes sign-in) with the release", plan.AuthDelegatorBinding)
	}
	if len(left) == 0 {
		deleteLeftoverHookJobs(ctx, plan, kube, &r)
	}
	r.Notes = append(r.Notes, PurgeSteps(plan)...)
	if len(left) > 0 {
		return r, restore(fmt.Errorf("%w on %d actor(s): %s. Delete them as an atespace editor "+
			"(kubectl ate delete egress-policy -a <atespace> <actor>), then uninstall again",
			ErrPoliciesLeft, len(left), strings.Join(left, ", ")))
	}
	return r, nil
}

// deleteLeftoverHookJobs removes the hook Jobs (and their pods) that earlier
// failed hooks left. A failure is a note: it never stops the uninstall.
func deleteLeftoverHookJobs(ctx context.Context, plan ChartPlan, kube KubeAPI, r *StepReport) {
	var gone []string
	for _, name := range LeftoverHookJobs {
		found, err := kube.DeleteJob(ctx, plan.Namespace, name)
		if err != nil {
			r.note("the hook Job %s could not be deleted (%v); delete it with kubectl -n %s delete job %s", name, err, plan.Namespace, name)
			continue
		}
		if found {
			gone = append(gone, name)
		}
	}
	if len(gone) > 0 {
		r.note("deleted the hook Job(s) %s and their pods, left by earlier failed hooks", strings.Join(gone, ", "))
	}
}

// ScaleBackTimeout bounds the scale-back after a failed uninstall step; it
// runs even when the hook's own context is cancelled.
var ScaleBackTimeout = 30 * time.Second

// stopController scales the controller to 0 and waits until no pod of it
// runs, terminating pods included. On any failure after the scale it puts
// the replicas back before it returns, so a failed uninstall never leaves the
// controller stopped with the policies in place (GAP-0056); stopped is then
// false.
func stopController(ctx context.Context, plan ChartPlan, kube KubeAPI, r *StepReport) (int32, bool, error) {
	if plan.ControllerDeployment == "" {
		r.note("the plan names no controller Deployment; nothing was stopped")
		return 0, false, nil
	}
	prev, found, err := kube.ScaleDeployment(ctx, plan.Namespace, plan.ControllerDeployment, 0)
	if err != nil {
		if found {
			// The scale may have gone through before the error.
			return 0, false, scaleBack(ctx, plan, kube, prev, r, err)
		}
		return 0, false, err
	}
	if !found {
		return 0, false, nil
	}
	deadline := time.Now().Add(ControllerStopTimeout)
	for {
		n, err := kube.DeploymentPods(ctx, plan.Namespace, plan.ControllerDeployment)
		if err != nil {
			return 0, false, scaleBack(ctx, plan, kube, prev, r, fmt.Errorf("count the pods of %s: %w", plan.ControllerDeployment, err))
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			return 0, false, scaleBack(ctx, plan, kube, prev, r, fmt.Errorf("%s still runs %d pod(s) after %s", plan.ControllerDeployment, n, ControllerStopTimeout))
		}
		select {
		case <-ctx.Done():
			return 0, false, scaleBack(ctx, plan, kube, prev, r, ctx.Err())
		case <-time.After(pollEvery):
		}
	}
	r.note("stopped %s (was %d replicas) so it cannot write policies during the uninstall", plan.ControllerDeployment, prev)
	return prev, true, nil
}

// scaleBack returns the controller to prev replicas after cause stopped the
// uninstall, and returns cause; when the scale-back fails too, the error
// says the controller is stopped and how to start it.
func scaleBack(ctx context.Context, plan ChartPlan, kube KubeAPI, prev int32, r *StepReport, cause error) error {
	if prev == 0 {
		return cause
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ScaleBackTimeout)
	defer cancel()
	if _, _, err := kube.ScaleDeployment(sctx, plan.Namespace, plan.ControllerDeployment, prev); err != nil {
		return fmt.Errorf("%w; and %s could not be scaled back to %d (%v): it is stopped while DefenseClaw policies remain with "+
			"nothing enforcing them; run: kubectl -n %s scale deployment/%s --replicas=%d",
			cause, plan.ControllerDeployment, prev, err, plan.Namespace, plan.ControllerDeployment, prev)
	}
	r.note("scaled %s back to %d: the uninstall stopped and the remaining policies stay enforced", plan.ControllerDeployment, prev)
	return cause
}

// sweepPolicies deletes every DefenseClaw egress policy and returns the
// actors whose policy could not be read or removed.
func sweepPolicies(ctx context.Context, plan ChartPlan, api SubstrateAPI, r *StepReport) ([]string, error) {
	actors, err := api.ListActors(ctx, "")
	if err != nil {
		// Fail closed: an unchecked uninstall could leave policies open.
		return nil, fmt.Errorf("list actors: %w. DefenseClaw cannot see the actors (is it a global viewer? the "+
			"bootstrap may never have run), so it cannot tell whether its egress policies remain. As a Substrate "+
			"admin, delete every egress policy that names %s (kubectl ate get egress-policy -a <atespace> <actor>), "+
			"then run helm uninstall --no-hooks", err, plan.ActorHost)
	}
	var left []string
	for _, a := range actors {
		p, err := api.GetEgressPolicy(ctx, a)
		if err != nil {
			left = append(left, fmt.Sprintf("%s (read: %v)", a, err))
			continue
		}
		if p == nil || !p.IsDefenseClaws(plan.ActorHost) {
			continue
		}
		if err := api.DeleteEgressPolicy(ctx, a); err != nil {
			left = append(left, fmt.Sprintf("%s (delete: %v)", a, err))
			continue
		}
		r.Removed = append(r.Removed, a.String())
	}
	return left, nil
}

func revokeProvider(ctx context.Context, plan ChartPlan, kube KubeAPI, r *StepReport) error {
	cp := plan.CredentialProvider
	cm, err := kube.GetConfigMap(ctx, plan.SubstrateNamespace, cp.ConfigMap)
	if err != nil || cm == nil {
		return err
	}
	// Every atespace granted the secrets namespaces, not only today's
	// launcher list: one removed from launcher_atespaces earlier keeps its
	// grant otherwise (GAP-0083). Only DefenseClaw grants those namespaces.
	grant, revoke := cp.grantedNamespaces()
	if prev := cm.Annotations[GrantedUserSecretsAnnotation]; prev != "" && prev != cp.SecretsNamespace {
		revoke = append(revoke, prev)
	}
	text := cm.Data[NamespacePolicyKey]
	var changes []GrantChange
	for _, ns := range append(grant, revoke...) {
		var revoked []GrantChange
		if text, revoked, err = RevokeNamespaceExcept(text, nil, ns); err != nil {
			return err
		}
		changes = append(changes, revoked...)
	}
	_, recorded := cm.Annotations[GrantedUserSecretsAnnotation]
	if len(changes) == 0 && !recorded {
		return nil
	}
	cm.Data[NamespacePolicyKey] = text
	delete(cm.Annotations, GrantedUserSecretsAnnotation)
	if err := kube.UpdateConfigMap(ctx, cm); err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	r.Grants = append(r.Grants, changes...)
	return kube.RestartDeployment(ctx, plan.SubstrateNamespace, cp.Deployment)
}

// PurgeSteps are the snapshot purge steps the uninstall prints (E10):
// suspended actors, forks and tags keep memory and disk snapshots in the
// Substrate bucket after DefenseClaw is gone.
func PurgeSteps(plan ChartPlan) []string {
	spaces := strings.Join(plan.LauncherAtespaces, " ")
	if spaces == "" {
		spaces = "<atespace>"
	}
	steps := []string{
		"Snapshots stay in the Substrate snapshot bucket (storage.snapshotLocation): actor memory, disk and volumes, " +
			"including anything an agent wrote. To purge them:",
		"  1. Delete the actors you no longer need, which removes their snapshots: for a in " + spaces +
			"; do kubectl ate get actors -a $a; done, then kubectl ate delete actor -a <atespace> <actor>.",
		"  2. Delete the tags (forks and checkpoints outlive their actors): kubectl ate get tags -a <atespace>, " +
			"then kubectl ate delete tag -a <atespace> <tag>.",
		"  3. Check the bucket prefix for objects of deleted actors and remove them with your cloud's tools.",
		"  4. The leader store volume (PVC defenseclaw-store) is kept on uninstall; delete it with " +
			"kubectl -n " + plan.Namespace + " delete pvc defenseclaw-store once you no longer need the audit history.",
		"  5. The access-policy grants stay (only a global owner can remove them), so a later ServiceAccount of the " +
			"same name would get them. As a global owner, take " +
			strings.Join(memberList(append(append([]string{}, plan.Editors...), plan.GlobalViewers...)), ", ") +
			" out of the global policy: kubectl ate get access-policy --global -o yaml > global.yaml, delete those " +
			"members from its bindings, then kubectl ate update access-policy --global -f global.yaml." + atespaceGrantSteps(plan),
	}
	steps = append(steps, "  6. The Secrets the install hooks created are kept, so a reinstall keeps chain joins and the images built with "+
		"the relay session key and the relay CA: "+ChainKeySecret+", "+CalloutTokenSecret+", "+plan.relaySessionSecret()+", "+plan.relayCASecret()+". Delete them with "+
		"kubectl -n "+plan.Namespace+" delete secret "+ChainKeySecret+" "+CalloutTokenSecret+" "+plan.relaySessionSecret()+" "+plan.relayCASecret()+
		" once nothing uses them (images built with the old relay session key then need a rebuild).")
	if plan.AuthDelegatorBinding != "" {
		steps = append(steps, "  7. After helm uninstall --no-hooks or a lost release, check the cluster-wide binding is gone: "+
			"kubectl delete clusterrolebinding "+plan.AuthDelegatorBinding+" --ignore-not-found.")
	}
	return steps
}

// atespaceGrantSteps is the same edit for each writable atespace's policy.
func atespaceGrantSteps(plan ChartPlan) string {
	if len(plan.WritableAtespaces) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(" Then the same for each atespace policy:")
	for _, a := range plan.WritableAtespaces {
		fmt.Fprintf(&sb, " kubectl ate get access-policy -a %s -o yaml > %s.yaml, delete the members, kubectl ate update access-policy -a %s -f %s.yaml;", a, a, a, a)
	}
	return strings.TrimSuffix(sb.String(), ";") + "."
}

func memberList(principals []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range principals {
		if m := Member(p); !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func orNone(s []string) []string {
	if len(s) == 0 {
		return []string{"no atespace"}
	}
	return s
}

// StepTimeout bounds one hook step.
const StepTimeout = 8 * time.Minute
