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

"""Policy-only v8 redaction mutations and secret-safe effective previews.

The Go compiler remains the sole owner of defaults, route expansion, profile
inheritance, generated destinations, and validation.  This module translates
operator intent into allow-listed surgical YAML mutations and compares the
masked effective plans produced by that compiler.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from defenseclaw.config import CONFIG_PATH_ENV, default_data_path
from defenseclaw.config_inspect import inspect_v8_config
from defenseclaw.file_permissions import set_file_mode
from defenseclaw.observability.v8_config import (
    BUCKETS,
    BUILT_IN_PROFILES,
    DETECTOR_GROUPS,
    FIELD_CLASSES,
    FIELD_MODES,
    SIGNALS,
    load_validate_v8,
)
from defenseclaw.observability.v8_yaml import (
    V8YAMLMutation,
    prepare_v8_yaml_write,
)

ASSIGNABLE_BUILT_IN_PROFILES: Final = tuple(profile for profile in BUILT_IN_PROFILES if profile != "legacy-v7")
CONTENT_SIGNALS: Final = frozenset({"logs", "traces"})
MANAGED_DESTINATION_NAME: Final = "managed-enterprise-ai-defense"
LOCAL_DESTINATION_NAME: Final = "local-sqlite"


@dataclass(frozen=True)
class EffectiveLeg:
    destination: str
    route: str
    bucket: str
    signal: str
    profile: str
    generated_destination: bool

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.destination, self.route, self.bucket, self.signal)


@dataclass(frozen=True)
class EffectiveLegChange:
    destination: str
    route: str
    bucket: str
    signal: str
    before: str
    after: str


@dataclass(frozen=True)
class RedactionPreview:
    before_sha256: str
    after_sha256: str
    before_plan_digest: str
    after_plan_digest: str
    changed: bool
    changes: tuple[EffectiveLegChange, ...]
    newly_unredacted: int
    no_longer_unredacted: int
    after_legs: tuple[EffectiveLeg, ...]
    warnings: tuple[tuple[str, str, str], ...]
    locked_profiles: tuple[tuple[str, tuple[str, ...]], ...]
    mutation_paths: tuple[str, ...]
    candidate: bytes = field(repr=False, compare=False, default=b"")


def load_redaction_source(config_path: str | Path) -> tuple[bytes, dict[str, Any]]:
    path = Path(config_path)
    raw = path.read_bytes()
    return raw, load_validate_v8(raw, source_name=str(path)).source


def redaction_profile_names(source: Mapping[str, Any]) -> tuple[str, ...]:
    observability = _observability(source)
    custom = observability.get("redaction_profiles")
    names = sorted(custom) if isinstance(custom, Mapping) else []
    return ASSIGNABLE_BUILT_IN_PROFILES + tuple(names)


def apply_profile_everywhere_mutations(
    source: Mapping[str, Any],
    profile: str,
) -> tuple[V8YAMLMutation, ...]:
    """Apply one profile to every configurable projection.

    A single baseline assignment plus deletion of every more-specific profile
    reference makes current and future configurable destinations inherit the
    requested value without changing collection or route selection.
    """

    _require_assignable_profile(source, profile)
    observability = _observability(source)
    mutations: list[V8YAMLMutation] = [V8YAMLMutation.set(("observability", "defaults", "redaction_profile"), profile)]
    buckets = observability.get("buckets")
    if isinstance(buckets, Mapping):
        for bucket in BUCKETS:
            policy = buckets.get(bucket)
            if isinstance(policy, Mapping) and "redaction_profile" in policy:
                mutations.append(V8YAMLMutation.delete(("observability", "buckets", bucket, "redaction_profile")))
    for index, destination in enumerate(_source_destinations(source)):
        send = destination.get("send")
        if isinstance(send, Mapping) and "redaction_profile" in send:
            mutations.append(
                V8YAMLMutation.delete(("observability", "destinations", index, "send", "redaction_profile"))
            )
        routes = destination.get("routes")
        if isinstance(routes, Sequence) and not isinstance(routes, (str, bytes, bytearray)):
            for route_index, route in enumerate(routes):
                if isinstance(route, Mapping) and "redaction_profile" in route:
                    mutations.append(
                        V8YAMLMutation.delete(
                            (
                                "observability",
                                "destinations",
                                index,
                                "routes",
                                route_index,
                                "redaction_profile",
                            )
                        )
                    )
    return tuple(mutations)


def defaults_mutations(
    source: Mapping[str, Any],
    *,
    profile: str | None = None,
    collect: Mapping[str, bool | None] | None = None,
    reset_profile: bool = False,
) -> tuple[V8YAMLMutation, ...]:
    mutations: list[V8YAMLMutation] = []
    if reset_profile:
        mutations.append(V8YAMLMutation.delete(("observability", "defaults", "redaction_profile")))
    elif profile is not None:
        _require_assignable_profile(source, profile)
        mutations.append(V8YAMLMutation.set(("observability", "defaults", "redaction_profile"), profile))
    for signal, enabled in (collect or {}).items():
        _require_signal(signal)
        if enabled is None:
            mutations.append(V8YAMLMutation.delete(("observability", "defaults", "collect", signal)))
        else:
            mutations.append(V8YAMLMutation.set(("observability", "defaults", "collect", signal), bool(enabled)))
    return tuple(mutations)


def bucket_mutations(
    source: Mapping[str, Any],
    bucket: str,
    *,
    profile: str | None = None,
    inherit_profile: bool = False,
    collect: Mapping[str, bool | None] | None = None,
) -> tuple[V8YAMLMutation, ...]:
    _require_bucket(bucket)
    mutations: list[V8YAMLMutation] = []
    if inherit_profile:
        mutations.append(V8YAMLMutation.delete(("observability", "buckets", bucket, "redaction_profile")))
    elif profile is not None:
        _require_assignable_profile(source, profile)
        mutations.append(V8YAMLMutation.set(("observability", "buckets", bucket, "redaction_profile"), profile))
    for signal, enabled in (collect or {}).items():
        _require_signal(signal)
        path = ("observability", "buckets", bucket, "collect", signal)
        mutations.append(V8YAMLMutation.delete(path) if enabled is None else V8YAMLMutation.set(path, bool(enabled)))
    return tuple(mutations)


def profile_set_mutations(
    source: Mapping[str, Any],
    name: str,
    *,
    extends: str | None,
    detectors: Sequence[str] | None,
    field_classes: Mapping[str, str | None],
) -> tuple[V8YAMLMutation, ...]:
    if name in BUILT_IN_PROFILES:
        raise ValueError(f"built-in profile {name!r} cannot be edited")
    observability = _observability(source)
    profiles = observability.get("redaction_profiles")
    existing = profiles.get(name) if isinstance(profiles, Mapping) else None
    if existing is not None and not isinstance(existing, Mapping):
        raise ValueError(f"custom profile {name!r} has an invalid source shape")
    result = dict(existing or {})
    if extends is not None:
        if extends not in {"sensitive", "content", "strict"}:
            raise ValueError("custom profiles must extend sensitive, content, or strict")
        result["extends"] = extends
    if "extends" not in result:
        raise ValueError("--extends is required when creating a custom profile")
    if detectors is not None:
        invalid = [value for value in detectors if value not in DETECTOR_GROUPS]
        if invalid:
            raise ValueError(f"unknown detector group(s): {', '.join(invalid)}")
        if not detectors:
            raise ValueError("custom profile detector list cannot be empty")
        result["detectors"] = list(dict.fromkeys(detectors))
    modes = dict(result.get("field_classes") or {})
    for field_class, mode in field_classes.items():
        if field_class not in FIELD_CLASSES:
            raise ValueError(f"unknown field class {field_class!r}")
        if mode is None:
            modes.pop(field_class, None)
        else:
            if mode not in FIELD_MODES:
                raise ValueError(f"unknown field mode {mode!r}")
            modes[field_class] = mode
    if modes:
        result["field_classes"] = modes
    else:
        result.pop("field_classes", None)
    return (V8YAMLMutation.set(("observability", "redaction_profiles", name), result),)


def profile_remove_mutations(
    source: Mapping[str, Any],
    name: str,
    *,
    replace_with: str | None = None,
) -> tuple[V8YAMLMutation, ...]:
    if name in BUILT_IN_PROFILES:
        raise ValueError(f"built-in profile {name!r} cannot be removed")
    profiles = _observability(source).get("redaction_profiles")
    if not isinstance(profiles, Mapping) or name not in profiles:
        raise ValueError(f"custom profile {name!r} does not exist")
    references = profile_reference_paths(source, name)
    if references and replace_with is None:
        raise ValueError(f"profile {name!r} is still referenced; select --replace-with before removing it")
    mutations: list[V8YAMLMutation] = []
    if replace_with is not None:
        _require_assignable_profile(source, replace_with)
        if replace_with == name:
            raise ValueError("replacement profile must differ from the removed profile")
        mutations.extend(V8YAMLMutation.set(path, replace_with) for path in references)
    mutations.append(V8YAMLMutation.delete(("observability", "redaction_profiles", name)))
    return tuple(mutations)


def profile_reference_paths(source: Mapping[str, Any], name: str) -> tuple[tuple[str | int, ...], ...]:
    observability = _observability(source)
    paths: list[tuple[str | int, ...]] = []
    defaults = observability.get("defaults")
    if isinstance(defaults, Mapping) and defaults.get("redaction_profile") == name:
        paths.append(("observability", "defaults", "redaction_profile"))
    buckets = observability.get("buckets")
    if isinstance(buckets, Mapping):
        for bucket in BUCKETS:
            policy = buckets.get(bucket)
            if isinstance(policy, Mapping) and policy.get("redaction_profile") == name:
                paths.append(("observability", "buckets", bucket, "redaction_profile"))
    for index, destination in enumerate(_source_destinations(source)):
        send = destination.get("send")
        if isinstance(send, Mapping) and send.get("redaction_profile") == name:
            paths.append(("observability", "destinations", index, "send", "redaction_profile"))
        routes = destination.get("routes")
        if isinstance(routes, Sequence) and not isinstance(routes, (str, bytes, bytearray)):
            for route_index, route in enumerate(routes):
                if isinstance(route, Mapping) and route.get("redaction_profile") == name:
                    paths.append(
                        (
                            "observability",
                            "destinations",
                            index,
                            "routes",
                            route_index,
                            "redaction_profile",
                        )
                    )
    return tuple(paths)


def destination_send_mutations(
    source: Mapping[str, Any],
    name: str,
    *,
    signals: Sequence[str],
    buckets: Sequence[str],
    profile: str | None,
) -> tuple[V8YAMLMutation, ...]:
    index, _ = source_destination(source, name)
    if not signals:
        raise ValueError("destination send policy requires at least one signal")
    if not buckets:
        raise ValueError("destination send policy requires at least one bucket or '*'")
    for signal in signals:
        _require_signal(signal)
    for bucket in buckets:
        if bucket != "*":
            _require_bucket(bucket)
    if "*" in buckets and len(buckets) != 1:
        raise ValueError("bucket wildcard must be the only bucket")
    send: dict[str, Any] = {
        "signals": list(dict.fromkeys(signals)),
        "buckets": list(dict.fromkeys(buckets)),
    }
    if profile is not None:
        _require_assignable_profile(source, profile)
        send["redaction_profile"] = profile
    return (
        V8YAMLMutation.delete(("observability", "destinations", index, "routes")),
        V8YAMLMutation.set(("observability", "destinations", index, "send"), send),
    )


def destination_inherit_mutations(source: Mapping[str, Any], name: str) -> tuple[V8YAMLMutation, ...]:
    index, _ = source_destination(source, name)
    return (
        V8YAMLMutation.delete(("observability", "destinations", index, "send")),
        V8YAMLMutation.delete(("observability", "destinations", index, "routes")),
    )


def route_upsert_mutations(
    source: Mapping[str, Any],
    destination_name: str,
    route: Mapping[str, Any],
    *,
    position: int | None = None,
    must_exist: bool | None = None,
) -> tuple[V8YAMLMutation, ...]:
    index, destination = source_destination(source, destination_name)
    name = route.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("route name is required")
    routes = [dict(item) for item in _routes(destination)]
    matches = [route_index for route_index, item in enumerate(routes) if item.get("name") == name]
    if len(matches) > 1:
        raise ValueError(f"route {name!r} is duplicated")
    if must_exist is True and not matches:
        raise ValueError(f"route {name!r} does not exist")
    if must_exist is False and matches:
        raise ValueError(f"route {name!r} already exists")
    if matches:
        existing_index = matches[0]
        routes[existing_index] = dict(route)
    else:
        insert_at = len(routes) if position is None else position
        if insert_at < 0 or insert_at > len(routes):
            raise ValueError("route position is outside the destination route list")
        routes.insert(insert_at, dict(route))
    return (
        V8YAMLMutation.delete(("observability", "destinations", index, "send")),
        V8YAMLMutation.set(("observability", "destinations", index, "routes"), routes),
    )


def route_remove_mutations(
    source: Mapping[str, Any], destination_name: str, route_name: str
) -> tuple[V8YAMLMutation, ...]:
    index, destination = source_destination(source, destination_name)
    routes = [dict(item) for item in _routes(destination)]
    remaining = [item for item in routes if item.get("name") != route_name]
    if len(remaining) == len(routes):
        raise ValueError(f"route {route_name!r} does not exist")
    path = ("observability", "destinations", index, "routes")
    return (V8YAMLMutation.set(path, remaining) if remaining else V8YAMLMutation.delete(path),)


def route_move_mutations(
    source: Mapping[str, Any],
    destination_name: str,
    route_name: str,
    *,
    position: int,
) -> tuple[V8YAMLMutation, ...]:
    index, destination = source_destination(source, destination_name)
    routes = [dict(item) for item in _routes(destination)]
    matches = [item for item in routes if item.get("name") == route_name]
    if len(matches) != 1:
        raise ValueError(f"route {route_name!r} does not exist exactly once")
    route = matches[0]
    routes = [item for item in routes if item.get("name") != route_name]
    if position < 0 or position > len(routes):
        raise ValueError("route position is outside the destination route list")
    routes.insert(position, route)
    return (V8YAMLMutation.set(("observability", "destinations", index, "routes"), routes),)


def source_destination(source: Mapping[str, Any], name: str) -> tuple[int, Mapping[str, Any]]:
    matches = [
        (index, destination)
        for index, destination in enumerate(_source_destinations(source))
        if destination.get("name") == name
    ]
    if len(matches) != 1:
        if name in {LOCAL_DESTINATION_NAME, MANAGED_DESTINATION_NAME}:
            raise ValueError(f"generated destination {name!r} is read-only")
        known = ", ".join(
            str(destination.get("name")) for destination in _source_destinations(source) if destination.get("name")
        )
        suffix = f"; configured destinations: {known}" if known else ""
        raise ValueError(f"no configurable destination named {name!r}{suffix}")
    return matches[0]


def apply_mutations_to_source(
    source_bytes: bytes,
    mutations: Iterable[V8YAMLMutation],
    *,
    source_name: str,
) -> tuple[bytes, dict[str, Any]]:
    prepared = prepare_v8_yaml_write(source_bytes, tuple(mutations), source_name=source_name)
    parsed = load_validate_v8(prepared.candidate, source_name=source_name).source
    return prepared.candidate, parsed


def preview_redaction_mutations(
    config_path: str | Path,
    mutations: Iterable[V8YAMLMutation],
    *,
    data_dir: str | None = None,
) -> RedactionPreview:
    path = Path(config_path).absolute()
    original = path.read_bytes()
    mutation_tuple = tuple(mutations)
    prepared = prepare_v8_yaml_write(original, mutation_tuple, source_name=str(path))
    load_validate_v8(prepared.candidate, source_name=str(path))
    source = load_validate_v8(original, source_name=str(path)).source
    effective_data_dir = _effective_data_dir(source, data_dir)
    before = _inspect_snapshot(original, effective_data_dir, "before")
    after = _inspect_snapshot(prepared.candidate, effective_data_dir, "after")
    before_legs = {leg.key: leg for leg in effective_legs(before.effective or {})}
    after_legs = {leg.key: leg for leg in effective_legs(after.effective or {})}
    changes: list[EffectiveLegChange] = []
    newly_unredacted = 0
    no_longer_unredacted = 0
    for key in sorted(set(before_legs) | set(after_legs)):
        old = before_legs.get(key)
        new = after_legs.get(key)
        before_profile = old.profile if old is not None else "not-delivered"
        after_profile = new.profile if new is not None else "not-delivered"
        if before_profile == after_profile:
            continue
        destination, route, bucket, signal = key
        changes.append(
            EffectiveLegChange(
                destination,
                route,
                bucket,
                signal,
                before_profile,
                after_profile,
            )
        )
        if after_profile == "none" and before_profile != "none":
            newly_unredacted += 1
        if before_profile == "none" and after_profile != "none":
            no_longer_unredacted += 1
    warnings = _effective_warnings(after.effective or {})
    after_leg_values = tuple(sorted(after_legs.values(), key=lambda item: item.key))
    return RedactionPreview(
        before_sha256=prepared.expected_sha256,
        after_sha256=prepared.candidate_sha256,
        before_plan_digest=before.plan_digest,
        after_plan_digest=after.plan_digest,
        changed=prepared.changed,
        changes=tuple(changes),
        newly_unredacted=newly_unredacted,
        no_longer_unredacted=no_longer_unredacted,
        after_legs=after_leg_values,
        warnings=warnings,
        locked_profiles=_locked_profiles(after.effective or {}),
        mutation_paths=tuple(_display_path(mutation.path) for mutation in mutation_tuple),
        candidate=prepared.candidate,
    )


def effective_legs(effective: Mapping[str, Any]) -> tuple[EffectiveLeg, ...]:
    result: list[EffectiveLeg] = []
    destinations = effective.get("destinations")
    if not isinstance(destinations, Sequence) or isinstance(destinations, (str, bytes, bytearray)):
        return ()
    for destination in destinations:
        if not isinstance(destination, Mapping):
            continue
        destination_name = str(destination.get("name") or "")
        generated = destination.get("generated") is True
        routes = destination.get("routes")
        if not isinstance(routes, Sequence) or isinstance(routes, (str, bytes, bytearray)):
            continue
        for route in routes:
            if not isinstance(route, Mapping) or route.get("action") != "send":
                continue
            route_name = str(route.get("name") or "")
            signals = route.get("signals")
            profiles = route.get("redaction_profile_by_bucket")
            if (
                not isinstance(signals, Sequence)
                or isinstance(signals, (str, bytes, bytearray))
                or not isinstance(profiles, Mapping)
            ):
                continue
            for signal in signals:
                if signal not in CONTENT_SIGNALS:
                    continue
                for bucket, profile in profiles.items():
                    if isinstance(bucket, str) and isinstance(profile, str):
                        result.append(
                            EffectiveLeg(
                                destination_name,
                                route_name,
                                bucket,
                                str(signal),
                                profile,
                                generated,
                            )
                        )
    return tuple(result)


def _inspect_snapshot(raw: bytes, data_dir: str, label: str):
    descriptor, snapshot = tempfile.mkstemp(
        prefix=f".defenseclaw-redaction-{label}-",
        suffix=".yaml",
    )
    try:
        # The snapshots can contain the complete source configuration. Protect
        # the sibling before its first byte on POSIX and native Windows.
        set_file_mode(descriptor, snapshot, 0o600, set_owner=True)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return inspect_v8_config(
            "effective",
            config_path=snapshot,
            data_dir=data_dir,
            environment_overrides={CONFIG_PATH_ENV: snapshot},
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(snapshot)
        except FileNotFoundError:
            pass


def _locked_profiles(effective: Mapping[str, Any]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    result: list[tuple[str, tuple[str, ...]]] = []
    destinations = effective.get("destinations")
    if not isinstance(destinations, Sequence) or isinstance(destinations, (str, bytes, bytearray)):
        return ()
    legs = effective_legs(effective)
    profiles_by_destination: dict[str, set[str]] = {}
    for leg in legs:
        profiles_by_destination.setdefault(leg.destination, set()).add(leg.profile)
    for destination in destinations:
        if (
            not isinstance(destination, Mapping)
            or destination.get("generated") is not True
            or destination.get("name") != MANAGED_DESTINATION_NAME
        ):
            continue
        name = str(destination.get("name") or "")
        profiles = tuple(sorted(profiles_by_destination.get(name, set())))
        if profiles:
            result.append((name, profiles))
    return tuple(result)


def _effective_warnings(effective: Mapping[str, Any]) -> tuple[tuple[str, str, str], ...]:
    raw = effective.get("warnings")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    result: list[tuple[str, str, str]] = []
    for warning in raw:
        if not isinstance(warning, Mapping):
            continue
        result.append(
            (
                str(warning.get("code") or "warning"),
                str(warning.get("path") or ""),
                str(warning.get("summary") or "configuration warning"),
            )
        )
    return tuple(result)


def _effective_data_dir(source: Mapping[str, Any], explicit: str | None) -> str:
    if explicit:
        return explicit
    configured = source.get("data_dir")
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    return str(default_data_path())


def _require_assignable_profile(source: Mapping[str, Any], profile: str) -> None:
    if profile == "legacy-v7":
        raise ValueError("legacy-v7 is migration-only and cannot be newly assigned")
    if profile not in redaction_profile_names(source):
        raise ValueError(f"unknown redaction profile {profile!r}")


def _require_bucket(bucket: str) -> None:
    if bucket not in BUCKETS:
        raise ValueError(f"unknown catalog-v1 bucket {bucket!r}")


def _require_signal(signal: str) -> None:
    if signal not in SIGNALS:
        raise ValueError(f"unknown observability signal {signal!r}")


def _observability(source: Mapping[str, Any]) -> Mapping[str, Any]:
    value = source.get("observability")
    return value if isinstance(value, Mapping) else {}


def _source_destinations(source: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    value = _observability(source).get("destinations")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _routes(destination: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    value = destination.get("routes")
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("destination routes have an invalid source shape")
    return tuple(item for item in value if isinstance(item, Mapping))


def _display_path(path: Sequence[str | int]) -> str:
    result = "$"
    for part in path:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


__all__ = [
    "ASSIGNABLE_BUILT_IN_PROFILES",
    "EffectiveLeg",
    "EffectiveLegChange",
    "LOCAL_DESTINATION_NAME",
    "MANAGED_DESTINATION_NAME",
    "RedactionPreview",
    "apply_mutations_to_source",
    "apply_profile_everywhere_mutations",
    "bucket_mutations",
    "defaults_mutations",
    "destination_inherit_mutations",
    "destination_send_mutations",
    "effective_legs",
    "load_redaction_source",
    "preview_redaction_mutations",
    "profile_reference_paths",
    "profile_remove_mutations",
    "profile_set_mutations",
    "redaction_profile_names",
    "route_move_mutations",
    "route_remove_mutations",
    "route_upsert_mutations",
    "source_destination",
]
