# Spec 003: Windows deferred config

**Status:** Partly implemented. The gateway and guardian wait loops and the
health `configuration` state ship. The installer's `--deferred-config` path
parses but is refused by the Windows lifecycle, so the setup cannot yet create
an install that has no config or target manifest.

This specification records how a Secure Client managed install can bring the
DefenseClaw services up before the managed `config.yaml` and the hook-guardian
`targets.yaml` arrive. Secure Client drops both files later. Each service
waits for its file within a bounded window. The health snapshot reports which
file is still missing.

- [Requirements](requirements.md)
- [Design](design.md)
- [Tasks](tasks.md)

Written from the code as it is. Where the code and an earlier plan disagree,
the code wins and the difference is called out.
