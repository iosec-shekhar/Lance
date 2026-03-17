"""
LANCE — Module Factory v0.6.0
Registry for all attack modules — security and safety.
"""
from __future__ import annotations

from lance.attacks.prompt_injection.module  import build_probes as build_prompt_injection,  get_module_info as info_prompt_injection
from lance.attacks.data_exfiltration.module import build_probes as build_data_exfiltration, get_module_info as info_data_exfiltration
from lance.attacks.jailbreak.module         import build_probes as build_jailbreak,         get_module_info as info_jailbreak
from lance.attacks.rag_poisoning.module     import build_probes as build_rag_poisoning,     get_module_info as info_rag_poisoning
from lance.attacks.model_dos.module         import build_probes as build_model_dos,         get_module_info as info_model_dos
# v0.6.0 — safety modules
from lance.attacks.bias.module              import build_probes as build_bias,              get_module_info as info_bias
from lance.attacks.pii_leakage.module       import build_probes as build_pii_leakage,       get_module_info as info_pii_leakage
from lance.attacks.toxicity.module          import build_probes as build_toxicity,          get_module_info as info_toxicity
from lance.attacks.misinformation.module    import build_probes as build_misinformation,    get_module_info as info_misinformation

# ── Registry ────────────────────────────────────────────────────────────────

MODULE_REGISTRY: dict[str, dict] = {
    # ── Security modules ──────────────────────────────────────────────────
    "prompt_injection": {
        "build_fn": build_prompt_injection,
        "info_fn":  info_prompt_injection,
        "category": "security",
    },
    "data_exfiltration": {
        "build_fn": build_data_exfiltration,
        "info_fn":  info_data_exfiltration,
        "category": "security",
    },
    "jailbreak": {
        "build_fn": build_jailbreak,
        "info_fn":  info_jailbreak,
        "category": "security",
    },
    "rag_poisoning": {
        "build_fn": build_rag_poisoning,
        "info_fn":  info_rag_poisoning,
        "category": "security",
    },
    "model_dos": {
        "build_fn": build_model_dos,
        "info_fn":  info_model_dos,
        "category": "security",
    },
    # ── Safety modules (v0.6.0) ───────────────────────────────────────────
    "bias": {
        "build_fn": build_bias,
        "info_fn":  info_bias,
        "category": "safety",
    },
    "pii_leakage": {
        "build_fn": build_pii_leakage,
        "info_fn":  info_pii_leakage,
        "category": "safety",
    },
    "toxicity": {
        "build_fn": build_toxicity,
        "info_fn":  info_toxicity,
        "category": "safety",
    },
    "misinformation": {
        "build_fn": build_misinformation,
        "info_fn":  info_misinformation,
        "category": "safety",
    },
}


def get_module(name: str) -> dict:
    """Return module entry by name. Raises KeyError if not found."""
    if name not in MODULE_REGISTRY:
        raise KeyError(f"Unknown module: '{name}'. Available: {list(MODULE_REGISTRY.keys())}")
    return MODULE_REGISTRY[name]


def get_all_modules() -> dict[str, dict]:
    return MODULE_REGISTRY


def get_modules_by_category(category: str) -> dict[str, dict]:
    """Return only modules of a given category: 'security' or 'safety'."""
    return {k: v for k, v in MODULE_REGISTRY.items() if v["category"] == category}


def build_all_probes(system_prompt: str = None, modules: list[str] = None) -> list[dict]:
    """Build probes for the given modules (or all if None)."""
    names   = modules or list(MODULE_REGISTRY.keys())
    probes  = []
    for name in names:
        entry    = get_module(name)
        build_fn = entry["build_fn"]
        probes.extend(build_fn(system_prompt=system_prompt))
    return probes


def list_modules() -> list[dict]:
    """Return info dicts for all registered modules."""
    return [entry["info_fn"]() for entry in MODULE_REGISTRY.values()]
