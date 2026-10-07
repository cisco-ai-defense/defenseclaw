# Okta on Linux: starter kit

Scripts and examples that let a Linux host read Okta users and groups through the
Okta LDAP Interface and SSSD, so DefenseClaw can pick a guardrail profile by Okta
group. The step-by-step guide is in the docs:
[Use Okta users on Linux](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity-okta/)
(source: `docs-site/content/docs/enterprise/identity-okta.mdx`).

DefenseClaw never calls Okta. It sees an Okta user the way it sees any other SSSD
account: the OS answers who the user is and which groups the user is in.

## Where this applies

- OSS per-user installs and the standalone enterprise profile on Linux.
- Not the Secure Client integration: it rejects guardrail profiles, so the profile
  examples here would fail validation there, and this kit does not change Secure
  Client behavior.
- A per-user install keeps its config in the user's own home, so the user can change
  their own profile. Enforced policy needs the standalone enterprise profile.

## What was tested, and what was not

Tested live, on RHEL 9.8 against one Okta org (okta.com) with the LDAP Interface:

- Okta users signing in over SSH with their Okta passwords, groups and POSIX values
  read through SSSD, profiles chosen by Okta group on per-user installs and on the
  standalone enterprise profile.
- SSSD 2.9.8 as shipped in RHEL 9 cannot bind to Okta. An SSSD 2.9.8 built with the
  `ldap_use_ppolicy` backport can (`build-sssd-ppolicy-backport.sh`).
- Every script in this folder, on that host and against that org (dry run first, then
  for real, then a second run that changes nothing).

Not tested: Ubuntu, Debian and SLES hosts; RHEL 10 and SSSD 2.10 or later (upstream
has `ldap_use_ppolicy`; we did not run it); Okta domains other than okta.com; macOS
and Windows hosts with Okta (Okta Device Access, Platform SSO, or accounts synced to
Active Directory are covered by the identity docs, not by this kit).

## Files

| File | What it does |
| --- | --- |
| `okta-ldap-setup.py` | Okta side, through the Okta API: `check`, `posix-schema`, `assign-posix`, `bind-role`, `signon-policy`. Needs `OKTA_ORG_URL` and `OKTA_API_TOKEN`. Write commands take `--dry-run`. |
| `sssd-okta.conf.tmpl` | The SSSD config that was run against Okta, with placeholders. |
| `install-sssd-okta.sh` | Host side: renders the template, checks it, installs `sssd.conf`, selects the authselect profile, writes the sshd drop-in, restarts SSSD. `--dry-run`, `--render-only`. |
| `verify-okta-identity.sh` | Read-only check of SSSD, `getent`, `id`, the InfoPipe UPN, and the profile DefenseClaw picks for each user. |
| `admin-config.example.yaml` | Machine config for the standalone enterprise profile with profiles by Okta group. |
| `user-config.example.yaml` | The same idea for a per-user install. |
| `build-sssd-ppolicy-backport.sh`, `backport-ppolicy.py` | Builds RHEL 9's SSSD 2.9.8 with the `ldap_use_ppolicy` option. Pinned to `sssd-2.9.8-4.el9_8.1`. Builds only, installs nothing. |

## Quick start

1. In the Okta Admin Console, turn on the LDAP Interface (Directory, Directory
   Integrations, Add LDAP Interface). Okta has no API for this step. Create the bind
   user, the Linux users and the groups, and an API token.
2. Prepare the org (set `OKTA_ORG_URL` and `OKTA_API_TOKEN` first):

   ```bash
   ./okta-ldap-setup.py posix-schema
   ./okta-ldap-setup.py assign-posix --users-from engineering --primary-group linux-users \
       --group contractors --group ml-research --dry-run
   ./okta-ldap-setup.py bind-role --bind-login ldap-bind@example.com
   ./okta-ldap-setup.py signon-policy --bind-login ldap-bind@example.com --group linux-users
   ./okta-ldap-setup.py check --bind-login ldap-bind@example.com --group linux-users
   ```

   Drop `--dry-run` to apply. Every command can be run again; it changes only what
   differs.
3. On the host, use an SSSD that has `ldap_use_ppolicy` (SSSD 2.10 or later, or the
   backport build), then, as root:

   ```bash
   export OKTA_BIND_PASSWORD='...'    # or --bind-password-file FILE, or type it at the prompt
   ./install-sssd-okta.sh --org example --bind-login ldap-bind@example.com \
       --allow-group linux-users --dry-run
   ./install-sssd-okta.sh --org example --bind-login ldap-bind@example.com \
       --allow-group linux-users
   ```

4. Check an Okta user and the profile DefenseClaw chooses:

   ```bash
   sudo ./verify-okta-identity.sh --user alice --expect-group ml-research \
       --expect-profile okta-observe --connector claudecode
   ```

5. Install DefenseClaw and deliver the profiles: `admin-config.example.yaml` for the
   standalone enterprise profile, `user-config.example.yaml` for a per-user install.

## Secrets

No script takes a secret as an argument. The Okta API token comes from
`OKTA_API_TOKEN` (or a prompt on a terminal). The bind user's password comes from a
file (mode 0600), `OKTA_BIND_PASSWORD`, or a prompt. The password ends up only in
`/etc/sssd/sssd.conf` (root, mode 0600), which is where SSSD needs it. Give the bind
user nothing but the read-only role that `bind-role` creates.

## Checks

```bash
shellcheck -x *.sh
ruff check okta-ldap-setup.py backport-ppolicy.py
```

Lab tooling (outage drills, cold-cache wipes, the test harnesses) is not part of this
kit.
