"""LANCE — RAG Poisoning Attack Module · OWASP LLM03"""
from pathlib import Path
from lance.attacks.module_factory import build_module, get_module_info as _info

PAYLOADS_FILE = Path(__file__).parent / "payloads.yaml"
MODULE_NAME = "rag_poisoning"
DISPLAY_NAME = "RAG Poisoning"
OWASP_REF = "LLM03"
DESCRIPTION = (
    "Supply chain attacks targeting retrieval corpora: corpus poisoning, "
    "embedding manipulation, misinformation injection, and semantic collision."
)

def build_probes(system_prompt=None, attack_ids=None, apply_mutations=True, mutator_names=None):
    probes = build_module(MODULE_NAME, DISPLAY_NAME, OWASP_REF, PAYLOADS_FILE, system_prompt, apply_mutations, mutator_names)
    if attack_ids:
        probes = [p for p in probes if p.get("seed_id") in attack_ids]
    return probes

def get_module_info():
    return _info(MODULE_NAME, DISPLAY_NAME, OWASP_REF, DESCRIPTION, PAYLOADS_FILE)
