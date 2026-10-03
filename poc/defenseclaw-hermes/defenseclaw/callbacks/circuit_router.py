"""DefenseClaw smart router — cost-based model tier selection."""

import os
from litellm.integrations.custom_logger import CustomLogger

DEFAULT_MODEL = os.environ.get("DEFENSECLAW_DEFAULT_MODEL", "defenseclaw-default")
QUALITY_MODEL = os.environ.get("DEFENSECLAW_QUALITY_MODEL", "defenseclaw-quality")

_SIMPLE_MAX_LEN = 300
_COMPLEXITY_KEYWORDS = [
    "analyze", "compare", "explain in detail", "write a",
    "implement", "design", "architecture", "refactor",
    "debug", "review", "summarize the following document",
]


class CircuitSmartRouter(CustomLogger):

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if call_type != "completion":
            return data
        messages = data.get("messages", [])
        if not messages:
            return data
        last_content = messages[-1].get("content", "")
        if not isinstance(last_content, str):
            return data
        if self._is_simple(last_content):
            data["model"] = DEFAULT_MODEL
        else:
            data["model"] = QUALITY_MODEL
        return data

    def _is_simple(self, query: str) -> bool:
        if len(query) > _SIMPLE_MAX_LEN:
            return False
        lower = query.lower()
        if any(kw in lower for kw in _COMPLEXITY_KEYWORDS):
            return False
        return True
