"""
LANCE — Prompt Injection Attack Module
OWASP LLM01 · MITRE ATLAS AML.T0051

Loads payloads from payloads.yaml, applies mutations,
and returns a list of probes ready to execute.
"""
from pathlib import Path
from typing import Optional
import yaml
from lance.engine.mutators.payload_mutator import mutate, DEFAULT_MUTATORS


PAYLOADS_FILE = Path(__file__).parent / "payloads.yaml"

OWASP_REF = "LLM01"
MODULE_NAME = "prompt_injection"

# Mutators applied to each payload by default
MUTATORS = DEFAULT_MUTATORS


def load_payloads() -> list[dict]:
    """Load seed payloads from YAML."""
    with open(PAYLOADS_FILE) as f:
        data = yaml.safe_load(f)
    return data.get("attacks", [])


def build_probes(
    system_prompt: Optional[str] = None,
    attack_ids: Optional[list[str]] = None,
    apply_mutations: bool = True,
    mutator_names: Optional[list[str]] = None,
) -> list[dict]:
    """
    Build a list of probe definitions for the orchestrator.

    Each probe dict contains:
      - attack_module: str
      - attack_type: str
      - payload: str
      - owasp_ref: str
      - mitre_atlas_ref: str
      - severity: str
      - success_indicators: list[str]
      - remediation: str
      - mutator_name: str (which mutation was applied)
      - seed_id: str (original payload ID)

    Args:
        system_prompt: The system prompt the target model is using
        attack_ids: Optionally limit to specific payload IDs
        apply_mutations: Whether to generate mutated variants
        mutator_names: Which mutators to apply (defaults to DEFAULT_MUTATORS)

    Returns:
        List of probe dicts, one per payload × mutator combination
    """
    seeds = load_payloads()

    if attack_ids:
        seeds = [s for s in seeds if s["id"] in attack_ids]

    probes = []
    _mutators = mutator_names or MUTATORS

    for seed in seeds:
        base_probe = {
            "attack_module": MODULE_NAME,
            "attack_type": seed["type"],
            "owasp_ref": seed.get("owasp_ref", OWASP_REF),
            "mitre_atlas_ref": seed.get("mitre_ref", ""),
            "severity": seed.get("severity", "high"),
            "success_indicators": seed.get("success_indicators", []),
            "remediation": seed.get("remediation", ""),
            "description": seed.get("description", ""),
            "seed_id": seed["id"],
        }

        if apply_mutations:
            mutations = mutate(seed["payload"], _mutators)
            for m in mutations:
                probes.append({
                    **base_probe,
                    "payload": m["mutated_payload"],
                    "mutator_name": m["mutator_name"],
                })
        else:
            probes.append({
                **base_probe,
                "payload": seed["payload"],
                "mutator_name": "identity",
            })

    return probes


def get_module_info() -> dict:
    """Return metadata about this attack module."""
    payloads = load_payloads()
    return {
        "name": MODULE_NAME,
        "display_name": "Prompt Injection",
        "owasp_ref": OWASP_REF,
        "description": (
            "Tests the model's resistance to instruction override attacks. "
            "Covers direct injection, system prompt leakage, role confusion, "
            "indirect RAG injection, and jailbreak techniques."
        ),
        "seed_count": len(payloads),
        "mutators": MUTATORS,
        "total_probes": len(payloads) * len(MUTATORS),
    }
