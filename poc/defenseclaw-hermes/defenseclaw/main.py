"""DefenseClaw — LiteLLM-powered LLM proxy + MCP gateway."""

import os
import litellm
from fastapi import FastAPI
from defenseclaw.callbacks.guardrails import DefenseClawGuardrail
from defenseclaw.callbacks.circuit_router import CircuitSmartRouter

app = FastAPI(title="DefenseClaw", version="0.1.0-poc")


def _register_callbacks():
    guardrail = DefenseClawGuardrail()
    router = CircuitSmartRouter()
    litellm.callbacks = [guardrail, router]


def _configure_litellm():
    litellm.drop_params = True
    litellm.set_verbose = os.environ.get("LITELLM_VERBOSE", "false").lower() == "true"


@app.on_event("startup")
async def startup():
    _configure_litellm()
    _register_callbacks()


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "defenseclaw"}


def create_app():
    """Entry point for uvicorn: defenseclaw.main:create_app"""
    return app
