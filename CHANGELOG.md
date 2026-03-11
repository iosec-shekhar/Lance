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
