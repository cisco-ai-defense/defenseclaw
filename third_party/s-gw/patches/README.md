# DefenseClaw patch queue

If DefenseClaw needs an s-gw change before its standalone release, store a
numbered `git format-patch` file here and list it in `series`. The module build
must apply the queue in that order and fail if any patch no longer applies.
Every patch must also have a matching standalone s-gw pull request or commit.

Current queue:

1. `0001-defenseclaw-native-runtime-boundary.patch` advances the package to
   0.2.0, adds the packaged Linux Secret Service helper contract, and hardens
   Windows helper command admission. It disables the bundled Node console,
   service, and app surfaces and intentionally contains no TypeScript proxy
   tokenizer, quarantine, restricted MCP fallback, or enrollment approval
   mutation. The DefenseClaw native gateway admits and launches the signed
   runner for raw proxy tokenization and user-presence approval.
2. `0002-defenseclaw-native-authorization-hardening.patch` rejects every CLI
   `--allow-command` enrollment path before store construction and removes
   native app, service, menu bar, and browser work from restricted setup.
   Command authorization and approval UI remain owned by the admitted native
   runner.
3. `0003-defenseclaw-setup-help.patch` makes `s-gw setup --help` and
   `s-gw setup -h` print the restricted DefenseClaw setup contract before any
   credential-store, service, or UI work.
4. `0004-defenseclaw-windows-launch-trust.patch` routes every Windows
   PowerShell child through the host-resolved trusted executable and keeps
   TypeScript test launchers portable across operating systems.
5. `0005-defenseclaw-credential-status.patch` fails closed when the bundled
   Linux credential helper returns malformed status and records the
   kernel-derived canonical PowerShell path used by Windows SSH key
   protection.
6. `0006-defenseclaw-standalone-parity.patch` rejects the standalone Windows
   login-start route before store construction, binds the host-selected
   PowerShell to the kernel-derived canonical executable by file identity, and
   keeps the DefenseClaw trust tests aligned with the shared Windows path helper.

The pinned upstream revision includes the standalone cross-platform parity,
dependency refresh, credential-source metadata, portable test launcher, and
side-effect-free setup help and Windows helper lifetime work from
`sgateway/s-gw#74`. The queue contains only DefenseClaw host adaptations.
