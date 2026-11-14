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
| Role and RoleBinding `defenseclaw-gateway-secrets`, in each namespace a Kubernetes source of `config.substrate.secrets` names | the secrets admin API writes those Secrets: create, plus get and patch by name (every Secret of the namespace for a `{person}` name); a source in the release or Substrate namespace fails the render |
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
| `substrate.actorKeys.url` | `""` | the key set the gateway verifies actor tokens with (`config.substrate.identity.keys_url`); empty is the idp Service, `https://idp.<substrate.namespace>.svc/openid/v1/jwks`. The token's `iss` is compared with `config.substrate.identity.issuer` as a string, so a unique per-cluster issuer need not resolve (GAP-0194). A URL on another in-cluster Service or a private address may need a change to `networkPolicy.egress` |
| `substrate.actorKeys.caConfigMap` | `""` | a ConfigMap (key `ca.crt`) with the PEM CA of the keys URL certificate, mounted on the gateway as `keys_ca_file`; empty is the servicedns trust bundle, which signs the idp Service certificate |
| `substrate.credentialProvider.*` | grant on, namespace `defenseclaw-actor-secrets` | the launcher atespaces' grant in the Kubernetes credential provider policy |
| `bootstrap.ownerTokenSecret` | "" | a global owner's token Secret (key `token`) for the OpenFGA bootstrap |
| `callout.judge.tokenSecret` | `defenseclaw-callout-judge` | the callout's token for the MCP tool verdict route on the admin Service; the chain-key hook creates this Secret when absent. `""` turns the route off (tools/call alerts on OSS, refused on managed) |
| `gateway.extraArgs` | [] | flags appended to the gateway's serve flags |
| `gateway.adminGroups` | [] | groups whose members are DefenseClaw administrators (`--admin-groups`); `config.substrate.identity.admin_groups` is the same list as a config key, and the two add up |
| `gateway.oidcCA.configMap` or `gateway.oidcCA.secret`, `gateway.oidcCA.key` | "", "", ca.crt | a private OIDC issuer's trust bundle from a ConfigMap or a Secret (the Secret wins): mounted read-only at `/etc/defenseclaw/oidc-ca/`, `--oidc-ca-file` set |
| `gateway.extraEnv`, `gateway.extraVolumes`, `gateway.extraVolumeMounts` | [] | added to the gateway container and pod |
| `gateway.args` | [] | replaces the whole container argument list (`serve --substrate ...` included); for an added flag use `gateway.extraArgs` |
| `gateway.authDelegatorBinding` | "" | name of the one cluster-wide object: the gateway's ClusterRoleBinding to `system:auth-delegator`, rendered only for the Kubernetes sign-in (no OIDC issuer); "" is `defenseclaw-auth-delegator-<namespace>-<release>` |
| `callout.actorSecrets.secretName` | "" | exposed `actor_secrets` values for exact-value DLP, mounted read-only in the callout (egress) and the gateway (/llm); sets `config.substrate.extproc.actor_secrets_dir` |
| `networkPolicy.adminFrom`, `networkPolicy.metricsFrom` | [] | extra peers for the admin and metrics ports |
| `deploymentMode` | "" | sets `config.deployment_mode`; `managed_enterprise` mounts `config.yaml` as one read-only file and gives each pod a data volume owned by the gateway account (`0700`, set by an init container running as root with only `CHOWN` and `FOWNER`), as the managed trust checks require. `managed.serviceAccountName` names that account (`nonroot`). |
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
| `observability.local.enabled` | false | a local OTel collector for trying the chart |
| `bundles.enabled`, `bundles.anchorsSecret`, `bundles.inbox` | off, `defenseclaw-bundle-anchors`, `defenseclaw-bundle-inbox` | signed policy bundles; see below |

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

## Upgrade, rollback, uninstall

- `helm upgrade` checks the new config, refuses a skipped minor (N-1 to N only) and rolls under the PDBs. The leader
  migrates the store at start after a backup.
- `helm rollback` to a release with an older store schema is refused, naming the backup.
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
