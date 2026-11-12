# defenseclaw-substrate

DefenseClaw for [Agent Substrate](https://github.com/agent-substrate/substrate) actors: the gateway, its leader,
the controller and the egress callout, in one namespace (one release per namespace). Tested with Substrate
`>=1.0.0 <1.1.0` on Kubernetes 1.34 or later (Substrate needs pod certificates).

## Install

```sh
kubectl create namespace defenseclaw-system
kubectl label namespace defenseclaw-system ate.dev/api-access=true   # Substrate admits only labelled namespaces to ate-api
# A one-time token of a Substrate global owner, for the OpenFGA bootstrap (deleted after use):
kubectl -n defenseclaw-system create secret generic ate-bootstrap-owner --from-file=token=owner.token
helm install defenseclaw oci://ghcr.io/cisco-ai-defense/charts/defenseclaw-substrate --version 1.0.10 \
  -n defenseclaw-system --set bootstrap.ownerTokenSecret=ate-bootstrap-owner -f my-values.yaml
defenseclaw substrate setup     # the SubstrateInstall overlay for ate-setup (callout, router client)
defenseclaw substrate doctor
```

Without `bootstrap.ownerTokenSecret`, `defenseclaw substrate setup --print-access-policies` prints the access policies
for an admin to apply.

## What it creates

| Object | Purpose |
|---|---|
| Deployment `defenseclaw-gateway` (HPA min 2, PDB) | stateless gateway: actor and admin listeners |
| Service `defenseclaw-actor` (port 80) | the actor listener only: the one DefenseClaw host in egress policies |
| Service `defenseclaw-admin` (port 443) | launcher, fleet and bundle APIs; never reachable from actors |
| Deployment `defenseclaw-gateway-leader` (1, Recreate), PVC `defenseclaw-store`, Service `defenseclaw-leader` | stateful steps (tool chains, intent, asks); the PVC is kept on uninstall |
| Deployment `defenseclaw-controller` (2, one active by lease, PDB) | policies, admission, drift, idle suspend |
| Deployment `defenseclaw-callout` (HPA min 2, PDB), Service, ConfigMap `defenseclaw-callout` | the atenet-egress ext_proc callout and its config |
| ConfigMap `defenseclaw-config` | config.yaml, rendered from `config:` (the single source) |
| NetworkPolicies | default deny; actor listener and callout from atenet-egress only; admin from this namespace (not worker pods) and `networkPolicy.adminFrom`; leader from the release |
| Hook Jobs | bootstrap (post-install/upgrade), pre-upgrade, pre-rollback, pre-delete |

## Values

Every value is checked by `values.schema.json`. The main ones:

| Value | Default | Meaning |
|---|---|---|
| `image.repository`, `image.tag`, `image.digest` | ghcr.io/cisco-ai-defense/defenseclaw-gateway, appVersion, "" | the digest wins over the tag; the release chart pins it |
| `config` | substrate section on | DefenseClaw config.yaml; the chart fills `substrate.services` and `substrate.api` |
| `config.substrate.launcher_atespaces` | {} | profile to atespaces; only DefenseClaw edits these |
| `managedAtespaces` | [] | other atespaces DefenseClaw writes egress policy in |
| `substrate.namespace`, `substrate.apiAddress`, `substrate.apiAudience` | ate-system | where Substrate runs |
| `substrate.credentialProvider.*` | grant on, namespace `defenseclaw-actor-secrets` | the launcher atespaces' grant in the Kubernetes credential provider policy |
| `bootstrap.ownerTokenSecret` | "" | a global owner's token Secret (key `token`) for the OpenFGA bootstrap |
| `callout.judge.tokenSecret` | "" | turns on the MCP verdict route on the admin Service |
| `callout.actorSecrets.secretName` | "" | exposed `actor_secrets` values for exact-value DLP |
| `networkPolicy.adminFrom`, `networkPolicy.metricsFrom` | [] | extra peers for the admin and metrics ports |
| `adminIngress.*` | off | an Ingress for launchers to the admin Service |
| `metrics.prometheusRule.enabled` | false | alert rules |
| `observability.local.enabled` | false | a local OTel collector for trying the chart |
| `bundles.enabled`, `bundles.anchorsSecret`, `bundles.inbox` | off, `defenseclaw-bundle-anchors`, `defenseclaw-bundle-inbox` | signed policy bundles; see below |

## Signed policy bundles

A bundle is signed with `defenseclaw-gateway enterprise bundle sign --platform linux --device-group <cluster group>` from a
directory whose `config.yaml` holds only `guardrail.profiles` (description and `sandbox`) and `guardrail.profile_assignments`
with `match.substrate`. It is applied to a stage: named atespaces, or `all` for every other atespace. The controller layers a
stage's active bundle over `config.yaml` for its atespaces; `substrate.admin` still tightens every profile.

1. Create the anchors Secret (key `bundle-anchors.json`, the enterprise anchors format) and give only administrators access to
   it: `kubectl -n <ns> create secret generic defenseclaw-bundle-anchors --from-file=bundle-anchors.json`.
2. Install with `--set bundles.enabled=true`.
3. Apply: `defenseclaw substrate bundle apply v3.dcbundle --stage canary --atespaces team-a`, then the same bundle with
   `--stage all`. Or write it to the inbox ConfigMap (`<stage>.dcbundle` binaryData, `<stage>.atespaces` data) from GitOps.
4. `defenseclaw substrate bundle status` shows each stage's active and previous bundle and the receipts;
   `defenseclaw substrate bundle rollback --stage canary` puts the previous bundle back after verifying it again.

A bundle that does not verify is refused with a receipt (bad signature, unknown or revoked key, edited content, another
tenant or device group, a version at or below the stage's floor). The controller re-verifies every stage on each refresh: when
a key is revoked or the anchors' `min_version` passes a stage's bundle, that stage's atespaces fall back to `config.yaml` and an
alert event is written. Inside the cluster, `defenseclaw-gateway substrate-bundle test --bundle v3.dcbundle --atespace team-a`
shows the profile and egress an actor would get before you apply.

## Upgrade, rollback, uninstall

- `helm upgrade` checks the new config, refuses a skipped minor (N-1 to N only) and rolls under the PDBs. The leader
  migrates the store at start after a backup.
- `helm rollback` to a release with an older store schema is refused, naming the backup.
- `helm uninstall` first removes every egress policy DefenseClaw wrote (actors fall back to deny-all) and the
  credential provider grant, and fails while any remain. It prints the snapshot purge steps. Then run
  `defenseclaw substrate setup --remove`.

## Known limits

- **The actor listener is plain HTTP inside the cluster.** Agent Substrate v1.0.0's egress gateway verifies an
  `https` rule's upstream only against the public CAs in its image, so it refuses a certificate from any in-cluster
  CA (CERTIFICATE_VERIFY_FAILED; checked on v1.0.0). Egress therefore reaches the actor Service with an `http` rule on
  port 80, and the NetworkPolicy admits only atenet-egress to that port. The actor's own connection to egress, and
  everything past DefenseClaw, stay as the policy says. The hop from egress to the gateway carries the actor JWT in
  the clear on the cluster network: someone who can read pod traffic on a node could replay it until it expires
  (15 minutes by default). Node and network access are out of scope (threat model B4); use a CNI with encryption
  (for example WireGuard) where that matters.
- **Use the full Service names.** An actor resolves only the names in its egress policy, so policies and agent
  settings use `defenseclaw-actor.<namespace>.svc.cluster.local`, never the short `.svc` name.
- **NetworkPolicy is a second layer.** Some CNIs apply a policy to a new pod a moment after it starts (kind's kindnet:
  about a second). Every listener authenticates its callers on its own.
