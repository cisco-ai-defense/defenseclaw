# Active Directory: sandbox policy by group

An example machine config for the standalone enterprise profile on Linux and
macOS computers joined to Active Directory, where the AD group a person is in
picks their guardrail profile and their OpenShell sandbox policy. The guide is
in the docs:
[Sandboxes on managed computers](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/runtime/sandboxes/)
(source: `docs-site/content/docs/enterprise/runtime/sandboxes.mdx`). How DefenseClaw
reads AD users and groups from the operating system is in
[Identity and authentication](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity/authentication/).

DefenseClaw never calls Active Directory. A Linux host that joined the domain
with `realm join` (SSSD and Kerberos) or a Mac bound with the directory service
tools answers who the user is and which groups the user is in, and DefenseClaw
reads that answer.

## Where this applies

- The standalone enterprise profile on Linux and macOS. Delivered with the
  enterprise package and `enterprise <os> ensure --config`; no MDM step.
- Not the Secure Client integration: it refuses every `sandbox` section.
- Not Windows: a Windows computer cannot run sandboxes. A `required_for` agent
  there is refused, or alerted with `when_unavailable: alert`.
- Not a per-user install. A profile's `sandbox` section is read by the managed
  gateway; on a per-user install `openshell.admin` is advisory because the user
  owns `config.yaml`.

## Files

| File | What it is |
| --- | --- |
| `sandbox-profiles.example.yaml` | Machine config with `enterprise.openshell`, an `openshell.admin` floor, three profiles with `sandbox` sections (contractors, engineering, an offline floor), assignments by AD group and `default_profile`. |

## Use it

1. Copy `sandbox-profiles.example.yaml`, then change the realm in the group
   names, the egress hosts, `request_access` and the connectors.
2. Make sure the people who run sandboxes can: members of `docker` (Docker
   driver) or `kvm` (MicroVM driver on Linux). `ensure` never adds anyone.
3. Apply it as root with `enterprise linux ensure --from-package --config FILE`
   (macOS: `enterprise macos ensure ...`) and read the warnings it prints.
4. Check a person before they sign in:
   `defenseclaw-gateway enterprise linux profile-explain --user alice@corp.example.com --connector claudecode`
   shows `effective.sandbox` with the source of every value, and
   `enterprise linux sandbox list` shows the sandboxes people started.

## What is checked, and what is not

The example passes the configuration validator that `ensure` runs first (it
loads with the managed sandbox keys, and a profile that names an unknown agent
in `required_for` is refused), and `ensure` prints no `default_profile`
warning for it: `offline-floor` repeats every setting of the assigned profiles,
so a directory outage does not give contractors less than their profile. A Go
test (`internal/config/identity_examples_test.go`) loads the file and fails if
that stops being true. If you loosen `offline-floor`, `ensure` names each setting
that is looser. The kit does not set up the domain, the join, SSSD
or the Mac binding; those are your directory's procedures. Entra Domain
Services and Okta use the same keys with their own group names (see the Okta
and Entra kits).
