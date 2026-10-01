# Spec 004: Windows UI IPC

**Status:** Implemented as a beta posture. Release builds are refused until
a follow-up spec adds Windows peer authentication.

On Windows, the managed-enterprise gateway serves the Secure Client UI over
an AF_UNIX socket under the trusted Program Files root. The server does not
authenticate peers on Windows. The socket DACL is the only access boundary,
and a compile-time gate stops a release build from shipping this posture.

- [Requirements](requirements.md)
- [Design](design.md)
- [Tasks](tasks.md)

Related: [spec 003](../003-windows-deferred-config/) defines the
configuration state carried on the health stream.
