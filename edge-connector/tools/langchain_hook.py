# TODO: Add unit tests (L-10)
"""LangChain/LangGraph Edge Connector middleware.

Wraps LangChain tools with DefenseClaw policy enforcement so every tool
call passes through the Edge Connector before execution.

Usage with LangChain:
    from langchain_hook import EdgeConnectorToolWrapper

    tools = [EdgeConnectorToolWrapper(tool) for tool in my_tools]
    agent = create_react_agent(llm, tools)

Usage with LangGraph:
    from langchain_hook import edge_connector_node

    graph.add_node("security_gate", edge_connector_node)
    graph.add_edge("agent", "security_gate")
    graph.add_edge("security_gate", "tools")

Requirements:
    pip install langchain-core  # minimal dependency
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Type, Union

from generic_hook import EdgeConnector, Verdict

logger = logging.getLogger("defenseclaw.langchain")

# ---------------------------------------------------------------------------
# Lazy imports — only loaded when actually used
# ---------------------------------------------------------------------------
_BaseTool = None
_ToolMessage = None
_BaseModel = None


def _import_langchain():
    global _BaseTool, _ToolMessage, _BaseModel
    if _BaseTool is None:
        from langchain_core.tools import BaseTool as BT
        _BaseTool = BT
    if _ToolMessage is None:
        try:
            from langchain_core.messages import ToolMessage as TM
            _ToolMessage = TM
        except ImportError:
            _ToolMessage = None
    if _BaseModel is None:
        try:
            from pydantic import BaseModel as BM
            _BaseModel = BM
        except ImportError:
            _BaseModel = None


# ---------------------------------------------------------------------------
# Shared connector singleton (lazily created)
# ---------------------------------------------------------------------------
_connector: Optional[EdgeConnector] = None


def get_connector(**kwargs: Any) -> EdgeConnector:
    """Return a module-level EdgeConnector, creating it on first call."""
    global _connector
    if _connector is None:
        _connector = EdgeConnector(**kwargs)
    return _connector


def set_connector(connector: EdgeConnector) -> None:
    """Override the module-level connector (useful for testing)."""
    global _connector
    _connector = connector


# ---------------------------------------------------------------------------
# EdgeConnectorTool — concrete BaseTool subclass wrapping any LangChain tool
# via composition (not dynamic class creation).
# ---------------------------------------------------------------------------
class _EdgeConnectorArgsSchema:
    """Lazy-built Pydantic model that mirrors the wrapped tool's args_schema."""

    @staticmethod
    def for_tool(tool: Any) -> Optional[Type]:
        """Return the wrapped tool's args_schema, or build a permissive one."""
        schema = getattr(tool, "args_schema", None)
        if schema is not None:
            return schema
        # Build a minimal schema that accepts arbitrary keyword arguments
        if _BaseModel is None:
            return None
        return type(
            f"{tool.name}_Schema",
            (_BaseModel,),
            {
                "__annotations__": {"input": str},
                "__module__": __name__,
            },
        )


def _build_edge_connector_tool(
    tool: Any,
    connector: Optional["EdgeConnector"] = None,
) -> Any:
    """Build a concrete ``BaseTool`` instance wrapping *tool* via composition.

    Uses a proper class definition with ``__module__`` set explicitly,
    avoiding the ``KeyError('__module__')`` that dynamic ``type()``
    construction triggers in some Pydantic v2 configurations.
    """
    _import_langchain()

    class EdgeConnectorTool(_BaseTool):
        """BaseTool that delegates to a wrapped tool via the Edge Connector."""

        name: str = tool.name
        description: str = tool.description
        args_schema: Optional[Type] = _EdgeConnectorArgsSchema.for_tool(tool)

        # Store the wrapped tool and connector as private attributes so
        # Pydantic does not attempt to validate them as model fields.
        _wrapped_tool: Any = None
        _wrapped_connector: Any = None

        class Config:
            arbitrary_types_allowed = True

        def __init__(self, **kwargs: Any):
            super().__init__(**kwargs)
            # Use object.__setattr__ to bypass Pydantic's frozen-model
            # protection on private attributes.
            object.__setattr__(self, "_wrapped_tool", tool)
            object.__setattr__(self, "_wrapped_connector", connector)

        def _run(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> str:
            # P2-13 fix: LangChain may pass tool_input as a keyword arg
            # (especially with structured tools / Pydantic schemas), in which
            # case the positional `tool_input` parameter is None. Merge kwargs
            # into a single arguments dict for the Edge Connector evaluation,
            # and forward correctly to the wrapped tool.
            ec = self._wrapped_connector or get_connector(fail_open=False)
            if tool_input is not None:
                arguments = {"input": tool_input, **kwargs} if kwargs else {"input": tool_input}
            elif kwargs:
                arguments = kwargs
            else:
                arguments = {}
            verdict_result = ec.evaluate(
                tool_name=self._wrapped_tool.name,
                arguments=arguments,
            )
            if verdict_result.blocked:
                msg = (
                    f"[EdgeConnector] Tool '{self._wrapped_tool.name}' blocked: "
                    f"{verdict_result.reason}"
                )
                logger.warning(msg)
                return msg
            # P2-13 fix: Forward correctly — use invoke() with the merged
            # arguments so LangChain's structured tool dispatch works.
            # When tool_input is None and kwargs are present, the wrapped
            # tool expects kwargs, not a None positional arg.
            if tool_input is not None:
                return self._wrapped_tool.invoke(tool_input, **kwargs)
            elif kwargs:
                return self._wrapped_tool.invoke(kwargs)
            else:
                return self._wrapped_tool.invoke("")

        async def _arun(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> str:
            ec = self._wrapped_connector or get_connector(fail_open=False)
            if tool_input is not None:
                arguments = {"input": tool_input, **kwargs} if kwargs else {"input": tool_input}
            elif kwargs:
                arguments = kwargs
            else:
                arguments = {}
            verdict_result = ec.evaluate(
                tool_name=self._wrapped_tool.name,
                arguments=arguments,
            )
            if verdict_result.blocked:
                msg = (
                    f"[EdgeConnector] Tool '{self._wrapped_tool.name}' blocked: "
                    f"{verdict_result.reason}"
                )
                logger.warning(msg)
                return msg
            # P2-13 fix: Same forward logic as _run for async path.
            if tool_input is not None:
                return await self._wrapped_tool.ainvoke(tool_input, **kwargs)
            elif kwargs:
                return await self._wrapped_tool.ainvoke(kwargs)
            else:
                return await self._wrapped_tool.ainvoke("")

    # Set __module__ explicitly to prevent KeyError in Pydantic introspection.
    EdgeConnectorTool.__module__ = __name__
    EdgeConnectorTool.__qualname__ = f"EdgeConnectorTool[{tool.name}]"

    return EdgeConnectorTool


class EdgeConnectorToolWrapper:
    """Wraps a LangChain ``BaseTool`` with Edge Connector enforcement.

    Call ``as_tool()`` (or just invoke the wrapper) to get a proper
    ``BaseTool`` instance that can be used anywhere a regular tool is
    expected.  When the agent invokes the tool, the wrapper evaluates
    the call through the Edge Connector first.  If the verdict is BLOCK
    the tool returns an error message instead of executing.
    """

    def __init__(
        self,
        tool: Any,
        connector: Optional[EdgeConnector] = None,
    ):
        _import_langchain()
        if not isinstance(tool, _BaseTool):
            raise TypeError(f"Expected a LangChain BaseTool, got {type(tool)}")
        self._tool = tool
        self._connector = connector

    def as_tool(self) -> Any:
        """Return a LangChain ``BaseTool`` wrapping the original tool."""
        cls = _build_edge_connector_tool(self._tool, self._connector)
        return cls()

    # Convenience: let callers use wrap() as a shortcut
    __call__ = as_tool


def wrap_tools(
    tools: List[Any],
    connector: Optional[EdgeConnector] = None,
) -> List[Any]:
    """Wrap a list of LangChain tools with Edge Connector enforcement."""
    return [
        EdgeConnectorToolWrapper(t, connector=connector).as_tool()
        for t in tools
    ]


# ---------------------------------------------------------------------------
# LangGraph node — intercepts tool calls in graph state
# ---------------------------------------------------------------------------
def edge_connector_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node that gates tool calls through the Edge Connector.

    Expected state keys:
        ``messages`` — list of LangChain message objects. The node inspects
        the last AI message for ``tool_calls`` and evaluates each one.

    Blocked tool calls are replaced with a ``ToolMessage`` containing the
    block reason.  Allowed calls are left in ``messages`` for the downstream
    tool node to execute.

    Usage::

        from langgraph.graph import StateGraph
        from langchain_hook import edge_connector_node

        graph = StateGraph(AgentState)
        graph.add_node("agent", agent_node)
        graph.add_node("security_gate", edge_connector_node)
        graph.add_node("tools", tool_node)
        graph.add_edge("agent", "security_gate")
        graph.add_edge("security_gate", "tools")
    """
    _import_langchain()
    ec = get_connector(fail_open=False)
    messages = state.get("messages", [])
    if not messages:
        return state

    last = messages[-1]
    tool_calls = getattr(last, "tool_calls", None)
    if not tool_calls:
        return state

    new_messages: list = []
    allowed_tool_calls: list = []
    for tc in tool_calls:
        name = tc.get("name", tc.get("function", {}).get("name", ""))
        args = tc.get("args", tc.get("function", {}).get("arguments", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {"raw": args}

        verdict = ec.evaluate(tool_name=name, arguments=args)

        if verdict.blocked:
            logger.warning("LangGraph gate: blocked %s (%s)", name, verdict.reason)
            if _ToolMessage is not None:
                tool_call_id = tc.get("id", "")
                new_messages.append(
                    _ToolMessage(
                        content=f"[EdgeConnector] Blocked: {verdict.reason}",
                        tool_call_id=tool_call_id,
                    )
                )
        else:
            allowed_tool_calls.append(tc)

    if new_messages:
        # Remove blocked tool_calls from the AIMessage so ToolNode does not
        # execute them.  We mutate a shallow copy of the last message to avoid
        # side-effects on the caller's original list.
        import copy
        patched_last = copy.copy(last)
        patched_last.tool_calls = allowed_tool_calls
        return {"messages": messages[:-1] + [patched_last] + new_messages}
    return state
