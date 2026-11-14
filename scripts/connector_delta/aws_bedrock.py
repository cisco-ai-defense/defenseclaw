# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Bounded Bedrock InvokeModel signing with temporary OIDC session credentials."""

import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit


def enabled():
    provider = os.environ.get("CONNECTOR_DELTA_AI_PROVIDER", "")
    if provider not in ("", "bedrock"):
        raise ValueError("unsupported AI provider")
    return provider == "bedrock"


def endpoint(model):
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
    if region not in ("us-east-1", "us-east-2", "us-west-2"):
        raise ValueError("Bedrock region is outside the approved US route")
    if not re.fullmatch(r"arn:aws:bedrock:" + region + r":\d{12}:application-inference-profile/[A-Za-z0-9]+", model):
        raise ValueError("Bedrock requires an application inference-profile ARN in the selected region")
    return f"https://bedrock-runtime.{region}.amazonaws.com/model/{quote(model, safe='')}/invoke"


def signed_headers(url, body, *, now=None):
    parsed = urlsplit(url)
    model = unquote(parsed.path.removeprefix("/model/").removesuffix("/invoke"))
    if url != endpoint(model):
        raise ValueError("unapproved Bedrock signing target")
    credentials = [
        os.environ.get(key, "") for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    ]
    if any(not value or len(value) > 16384 or any(not 33 <= ord(c) <= 126 for c in value) for value in credentials):
        raise ValueError("temporary AWS session credentials are required")
    access, secret, token = credentials
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    region = parsed.netloc.split(".")[1]
    digest = hashlib.sha256(body).hexdigest()
    headers = {
        "content-type": "application/json",
        "host": parsed.netloc,
        "x-amz-content-sha256": digest,
        "x-amz-date": stamp,
        "x-amz-security-token": token,
    }
    names = ";".join(sorted(headers))
    # SigV4 re-encodes the HTTP path, including the profile ARN's percent escapes.
    canonical = "\n".join(
        [
            "POST",
            quote(parsed.path, safe="/~"),
            "",
            "".join(f"{key}:{headers[key]}\n" for key in sorted(headers)),
            names,
            digest,
        ]
    )
    scope = f"{stamp[:8]}/{region}/bedrock/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret).encode()
    for part in (stamp[:8], region, "bedrock", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
    )
    return headers
