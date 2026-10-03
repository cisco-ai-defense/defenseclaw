"""DefenseClaw MCP secret resolver — injects credentials from env."""

import os
from litellm.integrations.custom_logger import CustomLogger

_SERVER_ENV_MAP = {
    "outlook": "OUTLOOK_OAUTH_TOKEN",
    "webex": "WEBEX_API_KEY",
    "websearch": "WEBSEARCH_API_KEY",
}


class MCPSecretResolver(CustomLogger):

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        tools = data.get("tools", [])
        for tool in tools:
            if tool.get("type") == "mcp":
                server = tool.get("server_name", "")
                env_var = _SERVER_ENV_MAP.get(server)
                if env_var:
                    token = os.environ.get(env_var, "")
                    if token:
                        tool["auth_headers"] = {"Authorization": f"Bearer {token}"}
        return data
