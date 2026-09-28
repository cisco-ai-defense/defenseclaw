#!/usr/bin/env bash
#
# Deprecated: the legacy openshell-sandbox (0.0.x) installer was removed.
#
# DefenseClaw no longer installs the standalone openshell-sandbox binary. This
# stub stays in the release so installers cached from earlier releases that
# still fetch it with --sandbox finish instead of failing. It prints a notice,
# changes nothing, and exits 0.
#
set -euo pipefail

main() {
    cat >&2 <<'EOF'
DefenseClaw: the legacy openshell-sandbox (0.0.x) installer has been removed.
  Nothing was installed. To run agents in NVIDIA OpenShell 0.1 sandboxes, run:
    defenseclaw sandbox setup
  To remove an old standalone sandbox install first, run:
    defenseclaw sandbox legacy-cleanup --dry-run
EOF
    return 0
}

main "$@"
# DefenseClaw OpenShell sandbox installer complete v1
