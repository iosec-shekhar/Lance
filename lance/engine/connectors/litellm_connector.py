"""
LANCE — Model Connector
Single interface for all LLM providers via LiteLLM.
Supports: OpenAI, Anthropic, Ollama (local), Azure OpenAI.
"""
import time
import asyncio
from typing import Optional
from dataclasses import dataclass
import litellm
from litellm import acompletion
from lance.config import settings

# Suppress litellm verbose logging
litellm.set_verbose = False


@dataclass
class ProbeResult:
    """Raw result from a single model call."""
    response_text: str
    latency_ms: int
    tokens_used: int
    model: str
    error: Optional[str] = None
    success: bool = True


SUPPORTED_PROVIDERS = {
    "openai": ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
    "anthropic": ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
    "ollama": ["llama3", "mistral", "phi3", "gemma", "llama2"],
}


def configure_keys():
    """Set API keys from settings into litellm."""
    if settings.openai_api_key:
        litellm.openai_key = settings.openai_api_key
    if settings.anthropic_api_key:
        litellm.anthropic_key = settings.anthropic_api_key


async def send_probe(
    model: str,
    payload: str,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 1024,
) -> ProbeResult:
    """
    Fire a single probe at a target model.

    Args:
        model: LiteLLM model string e.g. "openai/gpt-4o", "anthropic/claude-sonnet-4-6", "ollama/llama3"
        payload: The attack prompt to send
        system_prompt: Optional system prompt to test against
        temperature: Model temperature
        max_tokens: Max tokens in response

    Returns:
        ProbeResult with response text, latency, and token count
    """
    configure_keys()

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": payload})

    # Configure Ollama base URL if needed
    api_base = None
    if model.startswith("ollama/"):
        api_base = settings.ollama_base_url

    start = time.monotonic()
    try:
        response = await acompletion(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            api_base=api_base,
            timeout=settings.probe_timeout_seconds,
        )
        latency_ms = int((time.monotonic() - start) * 1000)

        response_text = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else 0

        return ProbeResult(
            response_text=response_text,
            latency_ms=latency_ms,
            tokens_used=tokens,
            model=model,
        )

    except Exception as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        return ProbeResult(
            response_text="",
            latency_ms=latency_ms,
            tokens_used=0,
            model=model,
            error=str(e),
            success=False,
        )


async def check_provider_connectivity(model: str) -> dict:
    """
    Test if a provider is reachable with a minimal probe.
    Returns dict with status and error if any.
    """
    test_result = await send_probe(
        model=model,
        payload="Reply with just the word: CONNECTED",
        max_tokens=10,
    )
    return {
        "model": model,
        "reachable": test_result.success,
        "error": test_result.error,
        "latency_ms": test_result.latency_ms,
    }
