// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// managedShellHTTPFailure is rendered only into standalone managed shell
// hooks. Every such hook uses this classifier for a complete HTTP reply and
// for a failed transfer with a known status. No status can be an outage,
// while an answered error or incomplete success is a response failure. The
// hook's own fail_response supplies its vendor-specific deny.
const managedShellHTTPFailure = `defenseclaw_managed_http_result() {
  local complete="${2:-complete}"
  case "$1" in
    ""|000)
      [ "$complete" = incomplete ] || fail_unreachable "gateway returned no HTTP status"
      return 0
      ;;
    2[0-9][0-9])
      [ "$complete" = incomplete ] && fail_response "gateway response incomplete"
      return 0
      ;;
    [0-9][0-9][0-9])
      if [ "$1" = 401 ] || [ "$1" = 403 ]; then
        if declare -F fail_unauthorized >/dev/null 2>&1; then
          fail_unauthorized "gateway returned HTTP ${1}"
        fi
      fi
      fail_response "gateway returned HTTP ${1}"
      ;;
    *)
      [ "$complete" = incomplete ] || fail_response "invalid HTTP status"
      return 0
      ;;
  esac
}

`
