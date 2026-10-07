#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Backport the ldap_use_ppolicy option to the SSSD 2.9.8 source tree of RHEL 9.8.

Okta's LDAP Interface answers the password-policy request control with a response control that has no
value. SSSD 2.9 cannot parse it and treats the bind as failed, so no Okta user resolves. Upstream SSSD
2.10.0 added the option ldap_use_ppolicy (issue 6666, commits 1980e2c4 and f22c966f). The upstream patch
does not apply to the RHEL 2.9.8 tree, so this script makes the same change in it by exact text
replacement (bind paths only; the password-change operation is unchanged).

Run it inside the prepared source tree (the folder that holds src/). Every edit must match exactly once.
On any other SSSD source it stops with the first text it did not find and changes nothing more; it is
pinned to sssd-2.9.8-4.el9_8.1.
"""

import os
import re
import sys

if not os.path.isfile("src/providers/ldap/ldap_opts.c"):
    sys.exit("run this inside the prepared SSSD 2.9.8 source tree (the folder that holds src/providers)")


def edit(path, old, new, count=1):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    found = text.count(old)
    if found != count:
        sys.exit(f"{path}: expected {count} match(es), found {found}: {old[:80]!r}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(old, new))
    print("edited", path)


PROVIDERS = "src/providers/"
CFG = "src/config/"

# The option, in the three providers that share the LDAP option table.
LAST_OPTION = (
    '    { "ldap_subid_ranges_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },\n'
    "    DP_OPTION_TERMINATOR"
)
NEW_OPTION = LAST_OPTION.replace(
    "    DP_OPTION_TERMINATOR",
    '    { "ldap_use_ppolicy", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },\n    DP_OPTION_TERMINATOR',
)
for name in ("ldap/ldap_opts.c", "ad/ad_opts.c", "ipa/ipa_opts.c"):
    edit(PROVIDERS + name, LAST_OPTION, NEW_OPTION)
edit(
    PROVIDERS + "ldap/sdap.h",
    "    SDAP_SUBID_RANGES_SEARCH_BASE,\n\n    SDAP_OPTS_BASIC",
    "    SDAP_SUBID_RANGES_SEARCH_BASE,\n    SDAP_USE_PPOLICY,\n\n    SDAP_OPTS_BASIC",
)

# sdap_auth_send() takes the new flag.
header = PROVIDERS + "ldap/sdap_async.h"
with open(header, encoding="utf-8") as handle:
    text = handle.read()
match = re.search(r"struct tevent_req \*sdap_auth_send\(.*?enum pwmodify_mode pwmodify_mode\);", text, re.S)
if not match:
    sys.exit("sdap_auth_send prototype not found")
prototype = match.group(0).replace(
    "enum pwmodify_mode pwmodify_mode);",
    "enum pwmodify_mode pwmodify_mode,\n                                  bool use_ppolicy);",
)
with open(header, "w", encoding="utf-8") as handle:
    handle.write(text[: match.start()] + prototype + text[match.end():])
print("edited", header)

# The bind code sends the request control only when the option is on.
conn = PROVIDERS + "ldap/sdap_async_connection.c"
edit(conn, "    bool use_start_tls;\n};", "    bool use_start_tls;\n    bool use_ppolicy;\n};")
edit(
    conn,
    "        rebind_proc_params->use_start_tls = state->use_start_tls;\n",
    "        rebind_proc_params->use_start_tls = state->use_start_tls;\n"
    "        rebind_proc_params->use_ppolicy = dp_opt_get_bool(state->opts->basic,\n"
    "                                                          SDAP_USE_PPOLICY);\n",
)
edit(
    conn,
    "                                           struct berval *pw,\n"
    "                                           enum pwmodify_mode pwmodify_mode)\n{",
    "                                           struct berval *pw,\n"
    "                                           enum pwmodify_mode pwmodify_mode,\n"
    "                                           bool use_ppolicy)\n{",
)
edit(
    conn,
    """    ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                  0, NULL, 0, &ctrls[0]);
    if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_control_create failed to create "
                  "Password Policy control.\\n");
        goto fail;
    }
    request_controls = ctrls;
""",
    """    if (use_ppolicy) {
        ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                      0, NULL, 0, &ctrls[0]);
        if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_control_create failed to create "
                                       "Password Policy control.\\n");
            goto fail;
        }
        request_controls = ctrls;
    }
""",
)
edit(
    conn,
    "                                  int simple_bind_timeout,\n"
    "                                  enum pwmodify_mode pwmodify_mode)\n{",
    "                                  int simple_bind_timeout,\n"
    "                                  enum pwmodify_mode pwmodify_mode,\n"
    "                                  bool use_ppolicy)\n{",
)
edit(
    conn,
    "simple_bind_send(state, ev, sh, simple_bind_timeout, user_dn, &pw, pwmodify_mode);",
    "simple_bind_send(state, ev, sh, simple_bind_timeout, user_dn, &pw, pwmodify_mode,\n"
    "                                  use_ppolicy);",
)
edit(
    conn,
    """                            dp_opt_get_int(state->opts->basic,
                                           SDAP_OPT_TIMEOUT),
                            state->opts->pwmodify_mode);""",
    """                            dp_opt_get_int(state->opts->basic,
                                           SDAP_OPT_TIMEOUT),
                            state->opts->pwmodify_mode,
                            dp_opt_get_bool(state->opts->basic,
                                            SDAP_USE_PPOLICY));""",
)
edit(
    conn,
    """    if (sasl_mech == NULL) {
        ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                      0, NULL, 0, &ctrls[0]);
        if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_ldap_control_create failed to create "
                      "Password Policy control.\\n");
            goto done;
        }
        request_controls = ctrls;
""",
    """    if (sasl_mech == NULL) {
        if (p->use_ppolicy) {
            ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                          0, NULL, 0, &ctrls[0]);
            if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_ldap_control_create failed to create "
                      "Password Policy control.\\n");
                goto done;
            }
            request_controls = ctrls;
        }
""",
)
edit(
    PROVIDERS + "ldap/ldap_auth.c",
    """                            dp_opt_get_int(state->ctx->opts->basic,
                                           SDAP_OPT_TIMEOUT),
                            state->ctx->opts->pwmodify_mode);""",
    """                            dp_opt_get_int(state->ctx->opts->basic,
                                           SDAP_OPT_TIMEOUT),
                            state->ctx->opts->pwmodify_mode,
                            dp_opt_get_bool(state->ctx->opts->basic,
                                            SDAP_USE_PPOLICY));""",
)
edit(
    PROVIDERS + "ipa/ipa_auth.c",
    """                            state->auth_ctx->sdap_auth_ctx->opts->pwmodify_mode);""",
    """                            state->auth_ctx->sdap_auth_ctx->opts->pwmodify_mode,
                            dp_opt_get_bool(state->auth_ctx->sdap_auth_ctx->opts->basic,
                                            SDAP_USE_PPOLICY));""",
)

# The option is known to the configuration schema.
edit(
    CFG + "etc/sssd.api.d/sssd-ldap.conf",
    "wildcard_limit = int, None, false\n",
    "wildcard_limit = int, None, false\nldap_use_ppolicy = bool, None, false\n",
)
rules = CFG + "cfg_rules.ini"
with open(rules, encoding="utf-8") as handle:
    text = handle.read()
sections = text.count("option = ldap_uri\n")
if sections < 1:
    sys.exit(f"{rules}: no 'option = ldap_uri' line found")
with open(rules, "w", encoding="utf-8") as handle:
    handle.write(text.replace("option = ldap_uri\n", "option = ldap_uri\noption = ldap_use_ppolicy\n"))
print("edited", rules, sections, "section(s)")
edit(
    CFG + "SSSDConfig/sssdoptions.py",
    "        'ldap_disable_range_retrieval': _('Disable Active Directory range retrieval'),\n",
    "        'ldap_disable_range_retrieval': _('Disable Active Directory range retrieval'),\n"
    "        'ldap_use_ppolicy': _('Use the ppolicy extension'),\n",
)
print("BACKPORT-OK")
