"""GAP-2640: an unprefixed Bedrock id resolves to the bedrock provider."""

import pytest

from defenseclaw.config import LLMConfig, is_bedrock_model_id
from defenseclaw.scanner._llm_env import litellm_model

HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


@pytest.mark.parametrize(
    ("model", "provider", "want"),
    [
        (HAIKU, "", "bedrock/" + HAIKU),
        ("us.openai.gpt-5.6-luna", "", "bedrock/us.openai.gpt-5.6-luna"),
        ("amazon.nova-pro-v1:0", "", "bedrock/amazon.nova-pro-v1:0"),
        ("bedrock/" + HAIKU, "", "bedrock/" + HAIKU),
        # Hard negatives: other providers' ids are unchanged.
        ("gpt-4o", "", "gpt-4o"),
        ("claude-haiku-4-5", "", "claude-haiku-4-5"),
        ("claude-haiku-4-5", "anthropic", "anthropic/claude-haiku-4-5"),
        ("llama3.1:8b", "ollama", "ollama/llama3.1:8b"),
    ],
)
def test_litellm_model_unprefixed_bedrock(model, provider, want):
    assert litellm_model(LLMConfig(model=model, provider=provider)) == want


def test_provider_prefix_infers_bedrock_only_for_bedrock_ids():
    assert LLMConfig(model=HAIKU).provider_prefix() == "bedrock"
    assert LLMConfig(model="gpt-4o").provider_prefix() == ""
    assert LLMConfig(model="mistral-large-latest").provider_prefix() == ""
    assert is_bedrock_model_id("eu.meta.llama3-2-1b-instruct-v1:0")
    assert not is_bedrock_model_id("gemini-2.5-pro")
