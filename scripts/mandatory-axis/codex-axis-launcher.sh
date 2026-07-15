#!/bin/sh
set -eu
umask 077
[ "$(id -un)" = cisco ] || { echo "managed launcher must be invoked by cisco" >&2; exit 77; }
[ "$#" -eq 0 ] || { [ "$1" = exec ] && [ "$#" -ge 2 ] || { echo "only interactive or codex exec is supported" >&2; exit 64; }; }
case "${CODEX_WORKSPACE:-/home/cisco/workspaces/defenseclaw}" in
  /home/cisco/workspaces/defenseclaw) ;;
  *) echo "unregistered workspace" >&2; exit 77 ;;
esac
curl --fail --silent --show-error http://127.0.0.1:18971/healthz >/dev/null
exec /usr/bin/bwrap --die-with-parent --new-session --unshare-pid --unshare-user --unshare-uts --unshare-ipc --proc /proc --dev /dev --tmpfs /tmp --ro-bind /home/cisco/workspaces/defenseclaw /home/cisco/workspaces/defenseclaw --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind /etc /etc --setenv HOME /var/lib/codex-axis/home --setenv CODEX_HOME /var/lib/codex-axis/home -- /opt/defenseclaw-axis/current/bin/codex-managed "$@"
