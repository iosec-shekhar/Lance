"""
LANCE — Generic Attack Module Factory
Loads any YAML-based attack module with a consistent interface.
All v2 modules (data_exfil, jailbreak, dos, rag_poisoning) use this.
"""
from pathlib import Path
from typing import Optional
import yaml
from lance.engine.mutators.payload_mutator import mutate, DEFAULT_MUTATORS


def build_module(
    module_name: str,
    display_name: str,
    owasp_ref: str,
    payloads_file: Path,
    system_prompt: Optional[str] = None,
    apply_mutations: bool = True,
    mutator_names: Optional[list[str]] = None,
) -> list[dict]:
    """Generic probe builder for any YAML-based attack module."""
    with open(payloads_file) as f:
        data = yaml.safe_load(f)
    seeds = data.get("attacks", [])

    _mutators = mutator_names or DEFAULT_MUTATORS
    probes = []

    for seed in seeds:
        base = {
            "attack_module": module_name,
            "attack_type": seed["type"],
            "owasp_ref": seed.get("owasp_ref", owasp_ref),
            "mitre_atlas_ref": seed.get("mitre_ref", ""),
            "severity": seed.get("severity", "high"),
            "success_indicators": seed.get("success_indicators", []),
            "remediation": seed.get("remediation", ""),
            "description": seed.get("description", ""),
            "seed_id": seed["id"],
        }
        if apply_mutations:
            for m in mutate(seed["payload"], _mutators):
                probes.append({**base, "payload": m["mutated_payload"], "mutator_name": m["mutator_name"]})
        else:
            probes.append({**base, "payload": seed["payload"], "mutator_name": "identity"})

    return probes


def get_module_info(module_name: str, display_name: str, owasp_ref: str, description: str, payloads_file: Path) -> dict:
    with open(payloads_file) as f:
        data = yaml.safe_load(f)
    seeds = data.get("attacks", [])
    return {
        "name": module_name,
        "display_name": display_name,
        "owasp_ref": owasp_ref,
        "description": description,
        "seed_count": len(seeds),
        "mutators": DEFAULT_MUTATORS,
        "total_probes": len(seeds) * len(DEFAULT_MUTATORS),
    }
