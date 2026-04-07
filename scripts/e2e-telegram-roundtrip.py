#!/usr/bin/env python3
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

"""Telegram round-trip E2E test.

Sends a test message to the OpenClaw bot via Telethon (as a real user),
then polls for a bot response containing the expected marker.

Required environment variables:
    E2E_TELEGRAM_API_ID          — Telegram API ID (from my.telegram.org)
    E2E_TELEGRAM_API_HASH        — Telegram API hash
    E2E_TELEGRAM_USER_SESSION    — Telethon session string
    E2E_TELEGRAM_BOT_USERNAME    — Bot username to message (e.g. @MyOpenClawBot)

Exit codes:
    0  — bot responded with expected marker
    1  — bot did not respond within timeout
    2  — configuration error
"""

from __future__ import annotations

import asyncio
import os
import sys
import time


def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"  ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return val


async def main() -> int:
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        print("  ERROR: telethon not installed (pip install telethon cryptg)", file=sys.stderr)
        return 2

    api_id = int(_require_env("E2E_TELEGRAM_API_ID"))
    api_hash = _require_env("E2E_TELEGRAM_API_HASH")
    session_str = _require_env("E2E_TELEGRAM_USER_SESSION")
    bot_username = _require_env("E2E_TELEGRAM_BOT_USERNAME")

    marker = f"TELEGRAM_OK_{int(time.time())}"
    prompt = f"E2E test: reply with exactly {marker}"
    timeout = 45

    client = TelegramClient(StringSession(session_str), api_id, api_hash)

    try:
        await client.connect()
        if not await client.is_user_authorized():
            print("  ERROR: Telethon session is not authorized — re-create the session string", file=sys.stderr)
            return 2

        print(f"  Sending to {bot_username}: {prompt}")
        await client.send_message(bot_username, prompt)

        deadline = time.time() + timeout
        while time.time() < deadline:
            messages = await client.get_messages(bot_username, limit=5)
            for msg in messages:
                if msg.out:
                    continue
                text = msg.text or ""
                if marker in text:
                    print(f"  Bot responded: {text[:120]}")
                    return 0
            await asyncio.sleep(3)

        print(f"  TIMEOUT: No response containing '{marker}' after {timeout}s")
        return 1

    finally:
        await client.disconnect()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
