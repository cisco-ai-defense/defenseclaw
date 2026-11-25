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
helm install defenseclaw oci://ghcr.io/cisco-ai-defense/charts/defenseclaw-substrate --version 1.0.11 \
  -n defenseclaw-system --set bootstrap.ownerTokenSecret=ate-bootstrap-owner -f my-values.yaml
defenseclaw substrate setup     # the SubstrateInstall overlay for ate-setup (callout, router client); GitOps: add --overlay-only
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
| Role and RoleBinding `defenseclaw-gateway-secrets`, in each namespace a Kubernetes source of `config.substrate.secrets` names | the secrets admin API writes those Secrets: create, plus get and patch by name (every Secret of the namespace for a `{person}` name); a source in the release or Substrate namespace fails the render |
| Role and RoleBinding `defenseclaw-<release namespace>-egress-read`, in the Substrate namespace (the chart's only standing grant there) | the controller's ServiceAccount alone: `get` on the `atenet-egress` ConfigMap alone (no list or watch, nothing else there), to detect a replaced egress callout (GAP-0505). The gateway gets the controller's result through the leader. Without the grant the controller warns and doctor says it cannot verify the egress callout |
| NetworkPolicies | default deny; actor listener and callout from atenet-egress only; admin from this namespace (not worker pods) and `networkPolicy.adminFrom`; leader from the release |
| Hook Jobs | bootstrap (post-install/upgrade), pre-upgrade, pre-rollback, pre-delete |

## Values

Every value is checked by `values.schema.json`. The main ones:

| Value | Default | Meaning |
|---|---|---|
| `image.repository`, `image.tag`, `image.digest` | ghcr.io/cisco-ai-defense/defenseclaw-gateway, appVersion, "" | the digest wins over the tag; the release chart pins it |
| `config` | substrate section on | DefenseClaw config.yaml; the chart fills `substrate.services` and `substrate.api` |
| `config.substrate.identity.revocation` | `{enabled: true, sync_interval: 5s, max_stale: 60s, max_tokens_per_person: 64}` | ended sign-ins: the leader keeps the list on its volume, each gateway replica pulls it every `sync_interval` and refuses sign-ins with `revocation_unavailable` when its copy is older than `max_stale`; `enabled` takes a gateway restart, and managed installs may not turn it off |
| `config.substrate.launcher_atespaces` | {} | profile to atespaces; only DefenseClaw edits these |
| `managedAtespaces` | [] | other atespaces DefenseClaw writes egress policy in |
| `substrate.namespace`, `substrate.apiAddress`, `substrate.apiAudience` | ate-system | where Substrate runs |
| `substrate.actorKeys.url` | `""` | the key set the gateway verifies actor tokens with (`config.substrate.identity.keys_url`); empty is the idp Service, `https://idp.<substrate.namespace>.svc/openid/v1/jwks`. The token's `iss` is compared with `config.substrate.identity.issuer` as a string, so a unique per-cluster issuer need not resolve (GAP-0194). A URL on another in-cluster Service or a private address may need a change to `networkPolicy.egress` |
| `substrate.actorKeys.caConfigMap` | `""` | a ConfigMap (key `ca.crt`) with the PEM CA of the keys URL certificate, mounted on the gateway as `keys_ca_file`; empty is the servicedns trust bundle, which signs the idp Service certificate |
| `substrate.credentialProvider.*` | grant on, namespace `defenseclaw-actor-secrets` | the launcher atespaces' grant in the Kubernetes credential provider policy |
| `substrate.launcher.keyReplay`, `substrate.files.push`, `substrate.files.sync` | unset (config defaults: `ask`, `true`, `true`) | Preview. The launcher key replay mode (`ask`, `on`, `off`; `off` is the admin-off switch) and the switches that refuse the upload of a push or a sync batch. Each fills `config.substrate.launcher.key_replay`, `files.push` and `files.sync` unless `config` sets it; `config` wins |
| `substrate.git.httpsRewrite`, `substrate.git.submodules`, `substrate.git.lfs`, `substrate.git.pushBranch` | unset (config defaults: the SaaS rewrites, `true`, `true`, `ask`) | Preview. Git in agents: extra ssh-to-https pairs (`from`, `to`; at most 64), whether `run --clone` clones submodules and fetches Git LFS files, and whether `pull --push-branch` may push (`allow`, `ask`, `deny`; `deny` is the admin-off switch). Each fills `config.substrate.git.https_rewrite`, `submodules`, `lfs` and `push_branch` unless `config` sets it; `config` wins |
| `bootstrap.ownerTokenSecret` | "" | a global owner's token Secret (key `token`) for the OpenFGA bootstrap |
| `callout.judge.tokenSecret` | `defenseclaw-callout-judge` | the callout's token for the MCP tool verdict route on the admin Service; the chain-key hook creates this Secret when absent. `""` turns the route off (tools/call alerts on OSS, refused on managed) |
| `gateway.extraArgs` | [] | flags appended to the gateway's serve flags |
| `gateway.adminGroups` | [] | groups whose members are DefenseClaw administrators (`--admin-groups`); `config.substrate.identity.admin_groups` is the same list as a config key, and the two add up |
| `gateway.oidcCA.configMap` or `gateway.oidcCA.secret`, `gateway.oidcCA.key` | "", "", ca.crt | a private OIDC issuer's trust bundle from a ConfigMap or a Secret (the Secret wins): mounted read-only at `/etc/defenseclaw/oidc-ca/`, `--oidc-ca-file` set |
| `gateway.extraEnv`, `gateway.extraVolumes`, `gateway.extraVolumeMounts` | [] | added to the gateway container and pod |
| `gateway.skillScanner.enabled` | false | Preview: the skill scanner sidecar (skill-scanner of this release) in the gateway pod; no port, no Secret mounts, no service-account token. true needs `gateway.skillScanner.image` to name an image the cluster can pull. false renders none and sets `config.substrate.skills.scan.enabled: false`, so new skills follow the fail mode |
| `gateway.skillScanner.image.repository`, `.tag`, `.digest` | ghcr.io/cisco-ai-defense/defenseclaw-scanner, the chart version, "" | the sidecar image; a digest wins over the tag |
| `gateway.skillScanner.resources` | 100m CPU and 256Mi requested, 1Gi limit | the sidecar's resources |
| `gateway.args` | [] | replaces the whole container argument list (`serve --substrate ...` included); for an added flag use `gateway.extraArgs` |
| `gateway.authDelegatorBinding` | "" | name of the one cluster-wide object: the gateway's ClusterRoleBinding to `system:auth-delegator`, rendered only for the Kubernetes sign-in (no OIDC issuer); "" is `defenseclaw-auth-delegator-<namespace>-<release>` |
| `gateway.relayCASecret` | `defenseclaw-relay-ca` | the relay CA (keys `ca.pem`, `ca-key.pem`, Preview): the gateway signs each relay's TLS serving certificate with it and checks the relay on attach (`config.substrate.relay_tls`). The relay-session hook creates it when absent and never replaces it; uninstall keeps it. To rotate it, make a new CA, put its certificate first in `ca.pem` with the old CA certificate after it, put the new key in `ca-key.pem`, and restart the gateway: it signs with the first CA and trusts both. Remove the old certificate from `ca.pem` after 24 hours (one relay certificate lifetime), when every relay has renewed onto the new CA; until then relays still on an old-CA certificate keep working. If the old CA key leaked, do not keep the old CA: put only the new CA certificate in `ca.pem` and the new key in `ca-key.pem`, and restart every gateway replica. The old CA is then no longer trusted, so whoever holds its key cannot mint relay certificates the gateway accepts. At the next attach the gateway refuses the relay's old certificate, and the relay asks for a new one at once: its renewal is refused (`renewal_ca_dropped`), so it asks again without proof, which follows `config.substrate.relay_cert_reissue`. With `flag` (the default outside managed installs) it gets a certificate from the new CA with a HIGH audit row, and attach works again. With `refuse` (the managed default) that request is refused with a HIGH audit row naming `previous_ca: dropped`, so for each running agent the owner or an administrator runs `defenseclaw substrate recover NAME` (list them with `defenseclaw substrate list`); the next attach then works. Suspending and resuming an agent also gives it a new certificate. Without either, attach to an agent fails until its old certificate expires (at most 24 hours) |
| `callout.actorSecrets.secretName` | "" | exposed `actor_secrets` values for exact-value DLP, mounted read-only in the callout (egress) and the gateway (/llm); sets `config.substrate.extproc.actor_secrets_dir` |
| `networkPolicy.adminFrom` | [] | extra peers for the admin port |
| `deploymentMode` | "" | sets `config.deployment_mode`; `managed_enterprise` mounts `config.yaml` as one read-only file and gives each pod a data volume (`managed.dataSizeLimit`, `4Gi`, sized as `homeSizeLimit`) owned by the gateway account (`0700`, set by an init container running as root with only `CHOWN` and `FOWNER`), as the managed trust checks require. `managed.serviceAccountName` names that account (`nonroot`). |
| `admin.expose.type` | `ClusterIP` | how laptops reach the admin listener (TLS): `ClusterIP` (in-cluster only), `LoadBalancer` (needs `admin.expose.loadBalancer.sourceRanges`, also enforced by the NetworkPolicy) or `Ingress` (needs `host` and `tlsSecretName`; re-encrypt to the HTTPS backend). The actor listener is never exposed. |
| `admin.url` | Ingress host, or the in-cluster admin Service | the https URL laptops use, published in ConfigMap `defenseclaw-launcher-endpoint` (key `admin_url`) that every authenticated user may read; `login --kube` sends a Kubernetes credential only to this URL. Required for `LoadBalancer`. |
| `admin.tlsSecretName` | "" | a `kubernetes.io/tls` Secret for the external name; without it the admin listener presents its in-cluster certificate |
| `controller.templateAnchorsSecret` | `defenseclaw-template-anchors` | admin-only Secret (key `anchors.pem`) with the template signing keys; without it every template is refused |
| `controller.templateRegistrySecret` | "" | a `kubernetes.io/dockerconfigjson` Secret with logins for private template registries, mounted read-only in the controller and the gateway (both read attestations); sets `config.substrate.templates.registry_auth.docker_config`. "" reads registries anonymously. See "Private template registries" |
| `config.substrate.templates.registry_auth.ecr_hosts` | [] | Amazon ECR registry hosts (`<account>.dkr.ecr.<region>.amazonaws.com`) the controller and the gateway log in to with `ecr:GetAuthorizationToken` through the AWS SDK default chain (IRSA or EKS Pod Identity); the token is renewed before it expires |
| `serviceAccounts.annotations`, `serviceAccounts.componentAnnotations.<gateway\|controller\|callout>` | {} | annotations on every ServiceAccount, and on one (merged over the first), for example an IRSA `eks.amazonaws.com/role-arn` on `gateway` and `controller` only |
| `substrate.podPorts` | `[443, 8443, 8445]` | container ports of the Substrate pods DefenseClaw calls (ate-api-server, the idp JWKS); NetworkPolicies match pod ports, so change them when a Substrate release moves a port |
| `substrate.router.enabled` | `true` | the gateway's attach route (run, connect, pull, logs, checkpoint) reaches actor relays through the atenet router; needs `podCertificates.enabled`. The router admits the gateway only when its SPIFFE ID is in Substrate's cluster-global `ingressAllowedSPIFFEIDs`: `defenseclaw substrate setup` adds it, `defenseclaw substrate doctor --cluster` checks it |
| `substrate.router.address` | `""` | router CONNECT-TLS `host:port`; empty is `atenet-router.<substrate.namespace>.svc:8444` |
| `substrate.router.serverName` | `""` | TLS name of the router certificate; empty is the address host |
| `substrate.router.caFile` | `/run/servicedns.podcert.ate.dev/trust-bundle.pem` | trust bundle for the router certificate (the servicedns bundle the gateway pod mounts) |
| `substrate.router.podPort` | `8444` | the router's container port, opened in the gateway's egress NetworkPolicy |
| `substrate.router.relayPort` | `8080` | the relay port inside the actor |
| `networkPolicy.egress.*` | on, OTLP 4317/4318 | egress limits for the gateway, leader and callout (DNS, Kubernetes and Substrate APIs, the release, OTLP; providers on 443 for gateway and leader) |
| `metrics.prometheusRule.enabled` | false | alert rules |
| `metrics.prometheusRule.namespaceLabel` | empty | empty: the policy alerts read every release's series (any OTLP receiver). `k8s_namespace_name`: they select this release, once your OTLP receiver or collector promotes `k8s.namespace.name` (without that they never fire) |
| `homeSizeLimit` | `4Gi` | the disk `emptyDir` each pod keeps `DEFENSECLAW_HOME` in outside managed mode: the local audit database (`audit.db` and its write-ahead log) and local state. An init container gives it to the gateway account (`0700`, as root with only `CHOWN` and `FOWNER`), as the audit store's directory trust check requires. It must hold `config.observability.local.max_store_mb` twice over plus 256 MiB for the write-ahead log; the chart refuses a smaller one. On this disk volume the kubelet evicts the pod at once when the volume passes `homeSizeLimit`: the local store is lost and no `ALERT audit_store_full` is logged (that alert comes from a write that finds no space: a memory volume, or a full node disk). The pods set no `ephemeral-storage` request, so the scheduler does not count this volume: leave room for `homeSizeLimit` per DefenseClaw pod on the nodes' disks. It is lost when the pod is replaced, and each gateway replica holds only what it handled; the durable audit record is an export destination under `config.observability.destinations` |
| `homeMedium` | "" | `""` is the disk volume above; `Memory` makes it a memory `emptyDir` (tmpfs) with no init container, for a namespace whose policy refuses a root init container. A tmpfs counts against the memory limit of the container that writes it, so the chart refuses `Memory` unless every DefenseClaw pod (`gateway`, `leader`, `controller`, `callout`) sets `resources.limits.memory` and `resources.requests.memory` with the limit at least `homeSizeLimit` plus the request (the request is the process headroom, never counted below the chart default request of that pod); otherwise the store would grow into an OOM kill instead of a full store. The defaults (`4Gi`, a `1024` MiB cap, limits of 512Mi to 2Gi) do not fit; see [A memory home volume](#a-memory-home-volume) |
| `config.observability.local.max_store_mb` | `1024` | the local audit store size cap (MiB): retention deletes the oldest audit history once the store passes nine tenths of it, down to seven tenths, the newest hour too when the cap needs it, checked every 30 seconds (a busy replica writes about 25 KB per hook post, about 4.3 GiB an hour at 50 posts a second). Required: without a cap the store can outgrow its volume. On the default disk volume the pod is then evicted and its local store lost; on a memory volume (or a full node disk) audit writes fail, every hook that needs an audit record fails closed, and the gateway log says `ALERT audit_store_full` |
| `observability.redactionProfile` | `sensitive` | the redaction profile of every record the gateway keeps in its audit store and sends, unless `config.observability.defaults.redaction_profile` names one: credentials, secrets and PII in prompts, model answers and tool results are replaced before they are written (GAP-0426). `none` keeps them whole; use it only when the store and every destination share an approved trust boundary |
| `observability.local.enabled` | false | a local OTel collector for trying the chart (debug exporter), and an otlp destination `chart-collector` to it in `config.observability.destinations` unless one with that name is set. For a real backend, add your own destination under `config.observability.destinations` |
| `bundles.enabled`, `bundles.anchorsSecret`, `bundles.inbox` | off, `defenseclaw-bundle-anchors`, `defenseclaw-bundle-inbox` | signed policy bundles; see below |
| `bundles.oci.enabled`, `bundles.oci.stages`, `bundles.oci.timeout`, `bundles.oci.authHosts` | off, [], "", [] | Preview: the controller pulls a stage's signed bundle by digest from an OCI registry; rendered into `config.substrate.bundles.oci` unless `config` sets it. Needs `bundles.enabled`; see "OCI registry bundles" |
| `bundles.oci.credentialsSecret`, `bundles.oci.ca.configMap` or `bundles.oci.ca.secret`, `bundles.oci.ca.key` | "", "", "", `ca.crt` | a `kubernetes.io/dockerconfigjson` Secret with the registry login and a PEM CA file for a private registry, mounted read-only in the controller only; set `oci.credentials_file` and `oci.ca_file` |

### A memory home volume

For a namespace that refuses the root init container (Pod Security `restricted`), size the volume, the cap and the limits together. `homeSizeLimit` must be at least twice `max_store_mb` plus 256 MiB, and each pod's memory limit at least `homeSizeLimit` plus its memory request:

```yaml
homeMedium: Memory
homeSizeLimit: 512Mi            # 2 x 128 + 256
config:
  observability:
    local:
      max_store_mb: 128
# gateway (request 256Mi, limit 1Gi) and leader (512Mi, 2Gi) fit as they are;
# controller and callout (request 128Mi) need 512Mi + 128Mi = 640Mi or more.
controller:
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {memory: 768Mi}
callout:
  resources:
    requests: {cpu: 250m, memory: 128Mi}
    limits: {memory: 768Mi}
```

`helm template` and `helm install` refuse a memory volume that a pod's limit can't hold, naming the values to change.

## Private template registries

The controller and the gateway's create path read each template image's attestation from its registry (only hosts in
`config.substrate.templates.allowed_images`). By default they read anonymously. For a private registry, give them a
login. Each login is sent only to its own host, after that host asks for it, and never to another registry or to a
token service it does not name:

- **Amazon ECR (EKS):** list the registry in `config.substrate.templates.registry_auth.ecr_hosts`, and give the gateway
  and controller ServiceAccounts an IAM role with `ecr:GetAuthorizationToken`, `ecr:BatchGetImage` and
  `ecr:GetDownloadUrlForLayer` on the template repositories. Use IRSA
  (`serviceAccounts.componentAnnotations.{gateway,controller}: {eks.amazonaws.com/role-arn: ...}`; it reaches STS on
  443), or EKS Pod Identity (also add a `networkPolicy.egress.extra` rule to `169.254.170.23/32` port 80). No password
  is stored, and the token is renewed before it expires.
- **Any other registry:** `kubectl -n <ns> create secret docker-registry dc-template-registry --docker-server=<host> ...`
  and `--set controller.templateRegistrySecret=dc-template-registry`. A Secret update applies within about a minute.

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
tenant or device group, a version at or below the stage's floor). The controller re-verifies every stage on each refresh.
When a stage's active bundle stops verifying (its key is revoked, the anchors are removed or their `min_version` passes it,
or the kept copy was changed), an alert event is written and that stage's atespaces get:

- **managed installs** (`config.deployment_mode: managed_enterprise`): deny-only. Actors keep only the DefenseClaw rule (the
  actor JWT to the actor listener, so hooks still get verdicts) until a trusted bundle is applied. A managed policy never
  loosens by itself.
- **OSS installs:** `config.yaml` again, as if no bundle had been applied.

Inside the cluster, `defenseclaw-gateway substrate-bundle test --bundle v3.dcbundle --atespace team-a`
shows the profile and egress an actor would get before you apply.

A stage names only atespaces DefenseClaw manages: a launcher atespace, or one that a `match.substrate` assignment of
`config.yaml` or of the bundle lists by name. Any other name is refused with a receipt (`stage_invalid`), and no stage is
made for it.

### OCI registry bundles (Preview)

Besides `bundle apply FILE` and the inbox ConfigMap, the controller can pull a stage's bundle by digest from an OCI registry.
It is off by default and adds no registry call until you turn it on. The registry is only transport: the bundle signature,
checked against the anchors Secret, decides what is enforced.

```yaml
bundles:
  enabled: true
  oci:
    enabled: true
    credentialsSecret: dc-bundle-registry   # optional: kubernetes.io/dockerconfigjson, key .dockerconfigjson
    ca:                                     # optional: a private registry CA, from a ConfigMap or a Secret
      configMap: registry-ca
      key: ca.crt
    authHosts: []                           # token realm hosts besides the registry (Docker Hub: auth.docker.io)
    stages:
    - stage: prod
      ref: registry.example.com/policy/prod-bundle@sha256:<64 hex>
      atespaces: [team-a, team-b]
```

- `ref` is `host/repository@sha256:<64 hex>`; a tag is refused. The artifact is an OCI image manifest with one layer of media
  type `application/vnd.defenseclaw.bundle.v1` (`oras push reg/repo:v7 prod.dcbundle:application/vnd.defenseclaw.bundle.v1`);
  pin the printed manifest digest.
- The login Secret and the CA are mounted read-only in the controller only, at
  `/etc/defenseclaw-substrate/bundle-oci-auth/config.json` and `/etc/defenseclaw-substrate/bundle-oci-ca/ca.crt`, and set
  `oci.credentials_file` and `oci.ca_file`. Without them the pull is anonymous and uses the system roots.
- If `config.substrate.bundles.oci` is set, the chart renders none of these keys: you keep full control of the file, and the
  mounts still apply when you name the Secret or CA.
- The controller's egress NetworkPolicy allows port 443. For a registry on another port, add a rule to
  `networkPolicy.egress.extra`.
- `helm template` refuses `bundles.oci.enabled` without `bundles.enabled` or without a stage, and a CA from both a ConfigMap
  and a Secret.

## Upgrade, rollback, uninstall

- `helm upgrade` checks the new config, refuses a skipped minor (N-1 to N only) and rolls under the PDBs. The leader
  migrates the store at start after a backup.
- `helm rollback` to a release with an older store schema is refused, naming the backup. A pre-rollback hook that
  fails for another reason (the store state cannot be read) leaves the same trouble. helm keeps the failed
  rollback as a revision in status pending-rollback (it writes the revision before it runs the hook), and every later
  `helm upgrade` fails with another operation in progress. Clear it with `helm -n NAMESPACE rollback RELEASE N`, where N is the
  revision `helm -n NAMESPACE history RELEASE` shows as deployed: that release passes the check and nothing changes. Every failed
  pre-rollback hook says this too. If the store-state ConfigMap itself cannot be parsed, every rollback fails the same
  way, so repair it first (`kubectl -n NAMESPACE edit configmap defenseclaw-store-state`: set `schema_version` to the
  schema the store is at, or delete the ConfigMap and the leader writes a new one), then clear the revision. helm prints only that the hook failed; the refusal, with these steps, is in
  `kubectl -n NAMESPACE logs job/defenseclaw-pre-rollback`.
- Outside managed mode every pod (gateway, leader, controller, callout) runs a root init container, `substrate-datadir`,
  with only `CHOWN` and `FOWNER`. A namespace that enforces the Pod Security `restricted` level, or OpenShift's
  `restricted` SCC, refuses those pods: on an upgrade from a chart without it, `helm upgrade` stalls with the old pods
  still running. There, set `homeMedium: Memory` (no init container) and size it as that row says before you upgrade.
- `helm uninstall` first stops the controller (it would write the policies again), then removes every egress policy
  DefenseClaw wrote (actors fall back to deny-all), looks again after a poll interval, and revokes every credential
  provider grant of the secrets namespace. It fails while any policy remains, and then scales the controller back so
  the remaining policies stay enforced. It prints the snapshot purge steps. Then run
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
- **In-cluster clients of the admin Service use `defenseclaw-admin.<namespace>.svc`.** Its certificate is the
  Substrate pod certificate, which names Services as `<svc>.<namespace>.svc` only, so the callout's verdict and ask
  calls (and the launcher endpoint's in-cluster default) use that name. With `admin.tlsSecretName`, the admin listener
  serves your certificate for external names and keeps the pod certificate for in-cluster Service names.
- **MCP body inspection needs an egress filter with mode override, and buffers the answer too.** Body mode needs
  Agent Substrate's egress filter rendered with `--experimental-additional-egress-extproc-allow-mode-override`
  (upstream #3817). Stock v1.0.0 ignores it: set `config.substrate.extproc.body_inspection: off` there (MCP calls are
  then checked on their headers only, and each one is recorded `body_not_inspected`). With `auto` on stock, every MCP
  request with a body is recorded `body_not_received` as an alert. #3817 allows one override mode, which buffers the
  response body as well, so a Streamable HTTP MCP server that answers a `tools/call` with an event stream reaches the
  agent only when the stream ends, and an answer over Envoy's buffer limit fails. Long-running tools that stream
  progress should answer with JSON or use the server's GET stream (never buffered). Requests the callout can't
  inspect (a body over 1 MiB, an event-stream, gRPC or multipart body) are refused when `failure_mode` is `closed`.
- **NetworkPolicy is a second layer.** Some CNIs apply a policy to a new pod a moment after it starts (kind's kindnet:
  about a second). Every listener authenticates its callers on its own.
