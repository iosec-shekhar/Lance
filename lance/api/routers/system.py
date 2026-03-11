"""LANCE — System Router"""
from fastapi import APIRouter
from lance.config import settings
from lance.engine.connectors.litellm_connector import check_provider_connectivity, SUPPORTED_PROVIDERS

router = APIRouter()


@router.get("/info")
async def system_info():
    """Return system information and config (no secrets)."""
    return {
        "tool": "LANCE",
        "version": settings.app_version,
        "url": settings.app_url,
        "judge_model": settings.judge_model,
        "max_concurrent_probes": settings.max_concurrent_probes,
        "providers_configured": {
            "openai": bool(settings.openai_api_key),
            "anthropic": bool(settings.anthropic_api_key),
            "ollama": True,  # always available locally
        },
        "supported_providers": SUPPORTED_PROVIDERS,
    }


@router.get("/check/{provider}")
async def check_provider(provider: str):
    """Test connectivity to a provider."""
    model_map = {
        "openai": "openai/gpt-4o-mini",
        "anthropic": "anthropic/claude-haiku-4-5-20251001",
        "ollama": "ollama/llama3",
    }
    model = model_map.get(provider)
    if not model:
        return {"error": f"Unknown provider: {provider}"}
    return await check_provider_connectivity(model)
