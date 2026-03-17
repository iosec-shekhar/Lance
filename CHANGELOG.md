## [0.6.0] — 2025-03-17

### Added — Attack Modules
- **Bias** (LLM09 / AML.T0048) — gender, race, political, religion sub-types. 20 seeds, 80 probes.
- **PII Leakage** (LLM06 / AML.T0024) — direct, session, database leakage sub-types. 20 seeds, 60 probes.
- **Toxicity** (LLM09 / AML.T0048) — profanity, insults, threats, harassment sub-types. 20 seeds, 80 probes.
- **Misinformation** (LLM09 / AML.T0048) — factual errors, unsupported claims, deepfake content. 20 seeds, 60 probes.
- Total modules: 9 (5 security + 4 safety). Total probes: 475+.

### Added — Attack Mutations (v0.6.0)
- **Leetspeak** — h3ll0 w0rld encoding to bypass keyword filters.
- **ROT-13** — classic obfuscation that evades simple content classifiers.
- **Math Problem Framing** — wraps payload as a word problem to distract safety layers.
- **Base64 Double Encode** — layered obfuscation via double base64.
- **ASCII Hex Encode** — payload as space-separated hex values.
- **Crescendo Primer** — gentle-start opening turn for multi-turn escalation.
- **Linear Jailbreak Primer** — DAN-style permissive context establishment.
- **Tree Branch Framing** — sneaks real payload among benign multiple-choice options.
- Total mutation strategies: 19 (was 10 in v0.5.0).

### Added — Multi-Turn Attack Chains
- `lance chain` CLI command — run YAML-defined conversation chains.
- `ChainEngine` — async multi-turn executor with per-turn judge scoring.
- 6 built-in chain templates:
  - `persona_anchoring` — establish unrestricted AI persona across turns.
  - `crescendo` — gentle escalation from benign to harmful across turns.
  - `context_poisoning` — incrementally inject false context.
  - `memory_exploitation` — plant false memories early, exploit later.
  - `jailbreak_escalation` — graduate from minor to major policy violations.
  - `linear_jailbreak` — DAN-mode establishment through repetition.

### Added — Custom Vulnerability API
- `CustomVulnerability` dataclass — define your own vulnerability in 5 lines.
- `load_custom_vuln_from_yaml()` — load custom vuln from YAML config.
- `build_probes_from_custom()` — generates direct + academic + hypothetical probes.

### Added — YAML Config Runner
- `lance run config.yaml` — run full multi-target assessments from config.
- Supports: multiple targets, module selection, chain templates, custom vulns, output folder, fail-on threshold, guardrails toggle.
- See `lance/config_runner/example_config.yaml` for full reference.

### Added — Guardrails
- `lance guardrail <campaign_id>` — re-fire confirmed findings to verify remediation.
- `GuardrailEngine` — async retry engine, configurable attempts, pass/fail summary.
- Covers all 9 modules including new safety modules.

### Added — NIST AI RMF Mapping
- All new safety modules (bias, pii_leakage, toxicity, misinformation) include NIST AI RMF references.
- GOVERN 1.1, MAP 5.1, MAP 5.2, MAP 2.3, MANAGE 2.4, MANAGE 4.1 coverage.

### Changed
- `payload_mutator.py` — expanded from 10 to 19 mutation strategies.
- `module_factory.py` — updated registry with 4 new modules + category field.
- `cli/main.py` — added `run`, `guardrail`, `chain` commands. Updated `MODULE_DISPLAY`.
- Version: 0.5.0 → 0.6.0.

---

# CHANGELOG

## v0.5.0 — Web UI Dashboard (Sessions 1–3)

### Added
- `lance ui` command — launches self-hosted Web UI at http://localhost:7777
- **Session 1** — FastAPI UI server (`lance/ui/server.py`) with SQLite persistence
- **Session 1** — WebSocket connection manager for live scan progress broadcasting
- **Session 2** — Dashboard page: campaign list, stats row, risk trend line chart, search/filter
- **Session 2** — Live scan progress via WebSocket with progress bar and message stream
- **Session 3** — Campaign detail page: 4 charts (severity doughnut, module bar, probe outcomes, OWASP radar)
- **Session 3** — Finding drawer: payload evidence, model response, OWASP/MITRE ref, remediation
- **Session 3** — Severity filter on findings table
- New Scan page: model picker, module checkboxes, system prompt input, launch overlay with live progress
- Full LANCE design system CSS (light CISO desk theme, matches website and pitch deck)
- Auto-open browser on `lance ui`
- Auto-refresh dashboard when running campaigns detected
- `lance serve` kept as headless REST API alias

### Changed
- Version bumped to 0.5.0
- `lance serve` now launches headless API only; `lance ui` is the recommended command

## v0.4.0 — Initial Release

- 5 attack modules: Prompt Injection, Data Exfiltration, Jailbreak, RAG Poisoning, Model DoS
- 195+ adversarial probes with 5 mutation strategies
- LLM-as-Judge scoring at 72% confidence threshold
- OWASP LLM Top 10 + MITRE ATLAS v4.5 mapping
- CVSS-aligned severity scoring
- HTML + PDF report generation
- CLI: scan, compare, list, report, check, modules
- GitHub Actions CI/CD workflow
- SQLite persistence via SQLAlchemy
