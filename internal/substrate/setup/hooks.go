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
	for _, h := range p.Hostnames {
		if h == actorHost || strings.HasPrefix(h, actorHost+":") || h == actorHost+".cluster.local" {
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
}

// KubeAPI is the part of the Kubernetes API the hook steps use. Not-found
// is (nil, nil) for GetConfigMap and nil for DeleteSecret.
type KubeAPI interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error)
	UpdateConfigMap(ctx context.Context, cm *ConfigMap) error
	// RestartDeployment rolls a Deployment (kubectl rollout restart).
	RestartDeployment(ctx context.Context, namespace, name string) error
	DeleteSecret(ctx context.Context, namespace, name string) error
}

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
func Bootstrap(ctx context.Context, plan ChartPlan, owner SubstrateAPI, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "bootstrap"}
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
	if plan.CredentialProvider.Grant && len(plan.LauncherAtespaces) > 0 {
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
	text, changes, err := GrantNamespace(cm.Data[NamespacePolicyKey], plan.LauncherAtespaces, cp.SecretsNamespace)
	if err != nil || len(changes) == 0 {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[NamespacePolicyKey] = text
	if err := kube.UpdateConfigMap(ctx, cm); err != nil {
		return fmt.Errorf("credential provider policy: %w", err)
	}
	r.Grants = append(r.Grants, changes...)
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
// schema than the store has, naming the backup (E25).
func PreRollback(ctx context.Context, plan ChartPlan, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "pre-rollback"}
	st, err := storeState(ctx, plan, kube)
	if err != nil {
		return r, err
	}
	return r, CheckRollback(plan.StoreSchema, st)
}

// ErrPoliciesLeft fails the uninstall while DefenseClaw-written egress
// policies remain: without DefenseClaw their hosts would stay open.
var ErrPoliciesLeft = errors.New("DefenseClaw egress policies remain")

// PreDelete removes every egress policy DefenseClaw wrote, so actors fall
// back to Substrate's default deny, then the credential provider grant. It
// fails while any of them remain, which stops `helm uninstall`.
func PreDelete(ctx context.Context, plan ChartPlan, api SubstrateAPI, kube KubeAPI) (StepReport, error) {
	r := StepReport{Step: "pre-delete"}
	actors, err := api.ListActors(ctx, "")
	if err != nil {
		return r, fmt.Errorf("list actors: %w", err)
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
	if plan.CredentialProvider.Grant && len(plan.LauncherAtespaces) > 0 {
		if err := revokeProvider(ctx, plan, kube, &r); err != nil {
			r.note("the credential provider grant stays: %v", err)
		}
	}
	r.Notes = append(r.Notes, PurgeSteps(plan)...)
	if len(left) > 0 {
		return r, fmt.Errorf("%w on %d actor(s): %s. Delete them as an atespace editor "+
			"(kubectl ate delete egress-policy -a <atespace> <actor>), then uninstall again",
			ErrPoliciesLeft, len(left), strings.Join(left, ", "))
	}
	return r, nil
}

func revokeProvider(ctx context.Context, plan ChartPlan, kube KubeAPI, r *StepReport) error {
	cp := plan.CredentialProvider
	cm, err := kube.GetConfigMap(ctx, plan.SubstrateNamespace, cp.ConfigMap)
	if err != nil || cm == nil {
		return err
	}
	text, changes, err := RevokeNamespace(cm.Data[NamespacePolicyKey], plan.LauncherAtespaces, cp.SecretsNamespace)
	if err != nil || len(changes) == 0 {
		return err
	}
	cm.Data[NamespacePolicyKey] = text
	if err := kube.UpdateConfigMap(ctx, cm); err != nil {
		return err
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
	return []string{
		"Snapshots stay in the Substrate snapshot bucket (storage.snapshotLocation): actor memory, disk and volumes, " +
			"including anything an agent wrote. To purge them:",
		"  1. Delete the actors you no longer need, which removes their snapshots: for a in " + spaces +
			"; do kubectl ate get actors -a $a; done, then kubectl ate delete actor -a <atespace> <actor>.",
		"  2. Delete the tags (forks and checkpoints outlive their actors): kubectl ate get tags -a <atespace>, " +
			"then kubectl ate delete tag -a <atespace> <tag>.",
		"  3. Check the bucket prefix for objects of deleted actors and remove them with your cloud's tools.",
		"  4. The leader store volume (PVC defenseclaw-store) is kept on uninstall; delete it with " +
			"kubectl -n " + plan.Namespace + " delete pvc defenseclaw-store once you no longer need the audit history.",
		"  5. The access-policy grants stay (only a global owner can remove them): take " +
			strings.Join(memberList(append(append([]string{}, plan.Editors...), plan.GlobalViewers...)), ", ") +
			" out of the global policy and of the policies of " + strings.Join(orNone(plan.WritableAtespaces), ", ") +
			" (kubectl ate get|update access-policy), so a later ServiceAccount of the same name gets nothing.",
	}
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
