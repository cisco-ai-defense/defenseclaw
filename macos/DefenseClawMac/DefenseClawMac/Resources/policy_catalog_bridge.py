# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Read-only projection of the selected runtime's TUI policy model.

Never applies commands. Intents are returned to the native confirmation view,
which dispatches them through CLIRunner and Activity. No config/secret dump.
"""
import json
import sys


def snapshot(config, sandbox_json="", sandbox_error=""):
    from defenseclaw.tui.policy_panel import read_policy_catalog
    from defenseclaw.tui.services import policy_state as p

    read = read_policy_catalog(config)
    model = p.PoliciesPanelModel()
    model.set_config(config)
    model.apply_policies(read.policies)
    model.apply_packs(read.global_pack, read.connectors, read.packs)
    model.apply_protection(read.postures, read.protection, pack_rules=read.pack_rules,
                           families=read.families, chains=read.chains, pack_bases=read.pack_bases)
    if sandbox_json:
        model.apply_sandbox_json(sandbox_json)
    else:
        model.set_sandbox_error(sandbox_error or "Sandbox pack catalog unavailable")

    def action(intent, group, consequence="", weaker=False):
        return dict(title=intent.label, group=group, arguments=list(intent.args),
                    consequence=consequence or intent.hint, weaker=weaker, mutation=True)

    def pack_actions(connector):
        result = []
        for pack in read.packs:
            value = pack.name if pack.kind == "preset" else pack.path
            overrides = model.override_connectors() if not connector else ()
            detail = f"Use {pack.name} ({pack.path}) for {connector or 'all connectors'}."
            if overrides:
                detail += " Clears connector pack overrides: " + ", ".join(overrides) + "."
            detail += " Explicit guardrail thresholds remain in effect. Validate the pack before changing it."
            result.append(action(p.use_pack_intent(value, connector), "Rule pack", detail,
                                 p.pack_weakens(model.packs_for_scope(connector), pack.name)))
            result[-1]["validationArguments"] = ["guardrail", "validate-pack", pack.path, "--json"]
            result.append(dict(title="Validate " + pack.name, group="Validate pack",
                               arguments=["guardrail", "validate-pack", pack.path, "--json"],
                               consequence="Validate without changing policy.", weaker=False, mutation=False))
        return result

    def actions():
        if model.view == "posture":
            row = model.selected_scope()
            if row is None:
                return []
            connector = model.command_connector(row)
            scope = connector or "global"
            out = []
            for mode in ("observe", "action"):
                detail = f"Change {scope} from {row.mode} to {mode}. Observe records findings without blocking tool calls."
                if not connector:
                    detail += " Connectors with their own mode keep it."
                out.append(action(p.mode_intent(mode, connector), "Mode", detail, p.mode_weakens(row.mode, mode)))
            for kind, levels in (("block", p.TOOL_BLOCK_LEVELS), ("alert", p.TOOL_ALERT_LEVELS)):
                for level in (*levels, p.INHERIT):
                    change = model.level_change(kind, row, level)
                    detail = "\n".join(f"{e.scope}: block {e.before.block_at} → {e.after.block_at}; alert {e.before.alert_at} → {e.after.alert_at}" for e in change.effects)
                    if change.keep_own:
                        detail += "\nKeep own values: " + ", ".join(change.keep_own)
                    detail += "\nThese levels govern tool calls, prompts, completions and LLM traffic in this scope."
                    out.append(action(p.level_intent(kind, level, connector), "Guardrail " + kind + " level", detail, bool(change.weakened())))
            for level in p.HILT_LEVELS:
                out.append(action(p.hilt_intent(level, connector), "Human approval",
                                  f"Set {scope} human approval from {row.hilt} to {level}. This changes when tool calls wait for a human.",
                                  p.hilt_weakens(row.hilt, level)))
            return out + pack_actions(model.connector_of(row))
        if model.view == "optin":
            pack = model.selected_protection()
            if pack is None or pack.status != "selectable":
                return []
            enable = pack.name not in model.scope_protection()
            connector = model.connector_of(model.selected_scope())
            return [action(p.protection_intent(pack.name, enable=enable, connector=connector),
                           "Protection", f"{'Enable' if enable else 'Disable'} {pack.title} for {connector or 'global'}. "
                           + pack.summary + " Existing custom rules are preserved by the runtime.", not enable)]
        if model.view == "policies":
            row = model.selected_policy()
            if row is None:
                return []
            active = model.active_policy()
            changes = [f"{label}: {old} → {new}" for label, old, new in p.policy_comparison(active, row)]
            changes += list(p.policy_side_effects(row))
            out = [action(p.activate_intent(row.name), "Activate", "\n".join(changes), bool(p.policy_weakenings(active, row)))]
            for kind, levels in (("block", p.BLOCK_LEVELS), ("alert", p.ALERT_LEVELS)):
                before = getattr(row, kind + "_at")
                for level in levels:
                    selected_policy = "" if row.active else row.name
                    effect = ("Changes the live global level for tool calls, prompts, completions and LLM traffic."
                              if row.active else "Saves this inactive policy; takes effect when activated.")
                    out.append(action(p.threshold_intent(kind, level, selected_policy), "Policy " + kind + " level",
                                      f"{row.name}: {kind} {before} → {level}. {effect}",
                                      p.threshold_weakens(before, level)))
            return out
        if model.view == "packs":
            row = model.selected_pack_row()
            return pack_actions("" if row.connector == "global" else row.connector) if row else []
        return []

    views = []
    scopes = [row.scope for row in model.postures] or ["global"]
    for scope_index, scope in enumerate(scopes):
        for view in p.POLICY_VIEWS:
            if scope_index and view not in ("optin", "families"):
                continue
            model.set_view(view)
            model.detail_open = True
            model.scope_index = scope_index
            columns, values = model.table(width=180)
            rows = []
            for index, cells in enumerate(values):
                # Chain domain headings are informational and have no actions.
                if view == "posture":
                    model.scope_index = index
                else:
                    model.cursors[view] = index
                rows.append(dict(id=str(index), cells=list(cells), detail=model.detail_text() or " · ".join(cells), actions=actions()))
            errors = [read.error if view == "policies" else "",
                      read.pack_error if view == "packs" else "",
                      read.posture_error if view in ("posture", "optin", "families", "chains") else "",
                      model.sandbox_error if view == "sandbox_packs" else ""]
            views.append(dict(id=view, scope=scope if view in ("optin", "families") else "",
                              title=p.VIEW_TITLES[view], columns=list(columns), rows=rows,
                              empty=model.empty_state(), error="; ".join(x for x in errors if x)))
    return dict(scopes=scopes, views=views)


if __name__ == "__main__":
    from defenseclaw import config as dc_config
    payload = json.loads(sys.stdin.read() or "{}")
    try:
        result = snapshot(dc_config.load(), payload.get("sandbox_json", ""), payload.get("sandbox_error", ""))
    except ModuleNotFoundError as error:
        if error.name not in ("defenseclaw.tui.policy_panel", "defenseclaw.tui.services.policy_state"):
            raise
        sys.exit("The selected DefenseClaw runtime does not include the Policies catalog. "
                 "Choose a compatible DefenseClaw CLI in Settings > Connection. "
                 "Update source installations with Git and make all; use the runtime updater for packaged installations.")
    print("DCPOLICY:" + json.dumps(result))
