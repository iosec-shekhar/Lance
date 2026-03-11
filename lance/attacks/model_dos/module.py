"""LANCE — Model DoS Attack Module · OWASP LLM04"""
from pathlib import Path
from lance.attacks.module_factory import build_module, get_module_info as _info

PAYLOADS_FILE = Path(__file__).parent / "payloads.yaml"
MODULE_NAME = "model_dos"
DISPLAY_NAME = "Model DoS"
OWASP_REF = "LLM04"
DESCRIPTION = (
    "Resource exhaustion attacks: token flooding, recursive loops, computation "
    "exhaustion, context window flooding, and sponge attacks targeting availability."
)

def build_probes(system_prompt=None, attack_ids=None, apply_mutations=True, mutator_names=None):
    # DoS probes don't benefit from most mutations — use identity only by default
    _mutators = mutator_names or ["identity", "role_play_wrapper", "hypothetical_wrapper"]
    probes = build_module(MODULE_NAME, DISPLAY_NAME, OWASP_REF, PAYLOADS_FILE, system_prompt, apply_mutations, _mutators)
    if attack_ids:
        probes = [p for p in probes if p.get("seed_id") in attack_ids]
    return probes

def get_module_info():
    return _info(MODULE_NAME, DISPLAY_NAME, OWASP_REF, DESCRIPTION, PAYLOADS_FILE)
