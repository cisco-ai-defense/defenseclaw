# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registry ingest pipeline.

Public surface:

* :func:`fetch_manifest`           — adapter dispatch
* :class:`Manifest` /
  :class:`ManifestEntry`           — parsed manifest shape
* :class:`SourceIndex` /
  :class:`EntryVerdict`            — on-disk per-source state
* :class:`SyncReport`              — return value of
                                     :func:`sync_source`
* :func:`sync_source` /
  :func:`sync_all`                 — drive ingest -> scan -> cache ->
                                     asset_policy promotion
* :func:`ManifestError` /
  :class:`IngestError` /
  :class:`SSRFError`               — typed errors
"""

from defenseclaw.registries.adapters import IngestError, fetch_manifest
from defenseclaw.registries.cache import (
    EntryVerdict,
    SourceIndex,
    cache_root,
    index_path,
    load_cached_manifest,
    load_index,
    manifest_path,
    remove_source,
    save_index,
    save_manifest,
    source_dir,
)
from defenseclaw.registries.manifest import (
    Manifest,
    ManifestEntry,
    ManifestError,
    parse_manifest,
)
from defenseclaw.registries.ssrf import SSRFError, guard_url
from defenseclaw.registries.sync import SyncReport, sync_all, sync_source

__all__ = [
    "EntryVerdict",
    "IngestError",
    "Manifest",
    "ManifestEntry",
    "ManifestError",
    "SSRFError",
    "SourceIndex",
    "SyncReport",
    "cache_root",
    "fetch_manifest",
    "guard_url",
    "index_path",
    "load_cached_manifest",
    "load_index",
    "manifest_path",
    "parse_manifest",
    "remove_source",
    "save_index",
    "save_manifest",
    "source_dir",
    "sync_all",
    "sync_source",
]
