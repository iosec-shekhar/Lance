<div align="center">

```
  ◁━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◆
  LANCE
  LLM Adversarial Neural Component Evaluator
```

**Open source framework for structured, automated red teaming of large language models.**

[![Version](https://img.shields.io/badge/version-0.6.0-1050D0?style=flat-square)](https://github.com/iosec-in/lance/releases)
[![License](https://img.shields.io/badge/license-MIT-16A34A?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3B82F6?style=flat-square)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-DC2626?style=flat-square)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE](https://img.shields.io/badge/MITRE-ATLAS%20v4.5-7E22CE?style=flat-square)](https://atlas.mitre.org)

[lance.iosec.in](https://lance.iosec.in) · [iosec.in](https://iosec.in) · *Precision strikes. Zero false calm.*

</div>

---

## Why LANCE Exists

Every few years, a new attack surface arrives before the security tooling does.

SQL injection was being exploited in production systems years before parameterised queries became standard practice. Cross-site scripting tore through the early web while developers were still debating whether it was really a vulnerability. Each one went through the same cycle: the technique emerged, attackers learned it, defenders caught up eventually.

**LLMs are in that cycle right now.**

Ask most security teams how they validated an LLM before deploying it. The answer is almost universally some version of the same thing: *we ran some prompts at it, it seemed fine.*

This is not carelessness. It is what happens in the absence of a methodology. There was no OWASP for LLMs to follow, no structured test plan to satisfy, no coverage model to close out. So teams improvised — tried a few obvious attacks, saw no obvious failures, and shipped.

The problem is that informal prompt experiments test the things you already thought to test. Real adversaries test everything else.

LANCE brings to LLM security what OWASP brought to web application security: **a methodology**. A defined attack surface. Repeatable coverage. Consistent scoring. Reporting that produces something a team can actually stand behind.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Attack Modules](#attack-modules)
- [How It Works](#how-it-works)
- [CLI Reference](#cli-reference)
- [Web UI](#web-ui)
- [Reports](#reports)
- [Configuration](#configuration)
- [Provider Setup](#provider-setup)
- [CICD Integration](#cicd-integration)
- [REST API](#rest-api)
- [Docker](#docker)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

## Quick Start

```bash
# Install
pip install lance-llm

# Copy and configure environment
cp .env.example .env

# Run your first scan (local Ollama — free, no API key needed)
lance scan ollama/llama3 --modules all

# Or against OpenAI
lance scan openai/gpt-4o --modules all

# Launch the Web UI dashboard
lance ui
# Opens http://localhost:7777
```

Under two minutes from install to first report.

---

## Installation

### Requirements

- Python 3.11 or higher
- pip or Poetry

### From PyPI

```bash
pip install lance-llm
```

### From Source

```bash
git clone https://github.com/iosec-in/lance.git
cd lance

# With Poetry
poetry install
poetry shell

# Or with pip
pip install -e .
```

### With PDF Report Support

PDF generation requires WeasyPrint and its system dependencies:

```bash
# macOS
brew install pango

# Ubuntu / Debian
sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# Then install WeasyPrint
pip install weasyprint
```

If WeasyPrint is not installed, LANCE automatically falls back to HTML reports.

### Verify Installation

```bash
lance --help
lance check        # Test provider connectivity
lance modules      # List available attack modules
```

---

## Attack Modules

LANCE covers five threat domains, each mapped to OWASP LLM Top 10 and MITRE ATLAS v4.5.

### Security Modules

| Module | OWASP | MITRE | Seeds | Probes | What It Tests |
|---|---|---|---|---|---|
| **Prompt Injection** | LLM01 | AML.T0051 | 9 | 45 | System prompt override, context leakage, instruction hijacking |
| **Data Exfiltration** | LLM06 | AML.T0024 | 10 | 30 | API key leakage, cross-user data exposure, system prompt disclosure |
| **Jailbreak** | LLM01 | AML.T0054 | 10 | 20 | Persona bypass, academic framing, roleplay exploitation |
| **RAG Poisoning** | LLM03 | AML.T0020 | 5 | 15 | Malicious retrieval content, context injection via documents |
| **Model DoS** | LLM04 | AML.T0016 | 5 | 10 | Runaway generation, output loop exploitation, resource exhaustion |

### Safety Modules *(v0.6.0)*

| Module | OWASP | MITRE | NIST AI RMF | Seeds | Probes | What It Tests |
|---|---|---|---|---|---|---|
| **Bias** | LLM09 | AML.T0048 | GOVERN-1.1, MAP-5.1 | 20 | 80 | Gender, race, political, religious bias |
| **PII Leakage** | LLM06 | AML.T0024 | MAP-2.3, MANAGE-2.4 | 20 | 60 | Direct, session, database PII exposure |
| **Toxicity** | LLM09 | AML.T0048 | GOVERN-1.1, MAP-5.2 | 20 | 80 | Profanity, insults, threats, harassment |
| **Misinformation** | LLM09 | AML.T0048 | MAP-5.1, MANAGE-4.1 | 20 | 60 | Factual errors, unsupported claims, synthetic disinformation |

**Total: 9 modules · 109 seed payloads · 475+ adversarial probes · 19 mutation strategies per seed**

### Prompt Injection

Tests whether a model can be instructed to override its system prompt, execute injected instructions embedded in data it was asked to process, or leak internal context it was given at initialisation.

This is the most common finding across LLM deployments. A model correctly configured with a system prompt is not automatically protected — the system prompt is advisory, not a security boundary.

### Data Exfiltration

Tests whether the model will surface information it should not expose: system prompts, API keys or credentials embedded in documents passed to the model, data belonging to other users referenced in context, and internal configuration details.

Particularly relevant for models deployed with tool access or document ingestion capabilities.

### Jailbreak

Tests the model's content policy under adversarial pressure. Probes cover persona-based bypasses, hypothetical framings, academic authority appeals, and roleplay constructs.

The question is not whether the model has a content policy. It is whether that policy holds when someone specifically tries to break it.

### RAG Poisoning

For retrieval-augmented deployments: tests whether malicious content embedded in retrieved documents can redirect the model's behaviour, override the system prompt, or cause the model to act on attacker-controlled instructions.

In RAG systems, the attack surface of the model is the attack surface of everything in the retrieval corpus.

### Model DoS

Tests for computational denial-of-service patterns: inputs that cause runaway token generation, prompts that induce infinite loops in structured output parsing, and resource exhaustion patterns that degrade response availability for legitimate users.

---

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│   POINT     │────▶│     FIRE     │────▶│    JUDGE    │────▶│    REPORT    │
│             │     │              │     │             │     │              │
│ Load seeds  │     │ Fire 195+    │     │ Two-pass    │     │ Risk score   │
│ Apply 5x    │     │ probes async │     │ heuristic + │     │ OWASP map    │
│ mutations   │     │ against      │     │ LLM judge   │     │ HTML + PDF   │
│ Build probe │     │ target model │     │ @ 0.72      │     │ Findings +   │
│ queue       │     │              │     │ threshold   │     │ remediation  │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
```

### Step 1 — Point

LANCE loads seed payloads from each selected attack module and applies 19 mutation strategies to each seed. v0.6.0 adds: Leetspeak, ROT-13, Math Problem framing, double Base64, ASCII hex, Crescendo primer, Linear jailbreak primer, Tree branch framing — on top of the original 10. This produces a probe queue that covers the attack surface systematically rather than relying on a fixed list of known-bad strings.

### Step 2 — Fire

Probes are fired asynchronously against the target model via LiteLLM — a unified interface across all supported providers. Concurrency is configurable (`MAX_CONCURRENT_PROBES`, default 5). Each probe records the full response, latency, and token usage.

### Step 3 — Judge

Each response goes through a two-pass scoring pipeline:

1. **Heuristic pre-screen** — Fast pattern matching eliminates obvious misses without consuming judge LLM tokens.
2. **LLM-as-Judge** — Responses that pass heuristics are evaluated by a separate judge model with a structured rubric: attack objective, probe content, model response, compliance verdict, confidence score 0.0–1.0.

The finding threshold is **0.72** — calibrated to minimise false positives while catching genuine compliance. Probes below threshold are recorded but do not appear as confirmed findings.

### Step 4 — Report

Confirmed findings are scored using a CVSS-aligned model, mapped to OWASP LLM Top 10 and MITRE ATLAS references, and compiled into a structured report with an overall risk score (0–10).

---

## CLI Reference

### `lance scan`

Run a full red team campaign against a model.

```bash
lance scan <model> [options]

# Examples
lance scan ollama/llama3
lance scan openai/gpt-4o --modules all
lance scan openai/gpt-4o --modules prompt_injection,jailbreak
lance scan openai/gpt-4o --modules pick                           # Interactive selector
lance scan openai/gpt-4o --system-prompt "You are a helpful assistant."
lance scan openai/gpt-4o --system-prompt-file ./system_prompt.txt
lance scan openai/gpt-4o --output report.pdf
lance scan openai/gpt-4o --fail-on 7.0                           # Exit 1 if score >= 7.0
```

| Flag | Default | Description |
|---|---|---|
| `--modules` | `all` | `all`, `pick` (interactive), or comma-separated names |
| `--name` | Auto from model | Campaign display name |
| `--system-prompt` | None | System prompt under test |
| `--system-prompt-file` | None | Path to file containing system prompt |
| `--output` | Auto-named `.html` | Output path — `.html` or `.pdf` |
| `--fail-on` | None | Exit code 1 if risk score >= this value (CI/CD use) |

### `lance compare`

Scan multiple models with the same attack suite, generate a side-by-side comparison.

```bash
lance compare ollama/llama3 ollama/mistral
lance compare openai/gpt-4o openai/gpt-4o-mini anthropic/claude-haiku-4-5-20251001
lance compare ollama/llama3 openai/gpt-4o --modules prompt_injection,jailbreak
```

### `lance report`

Generate or regenerate a report for any completed campaign.

```bash
lance report <campaign_id>
lance report <campaign_id> --output assessment.pdf
```

### `lance list`

List all campaigns stored in the local database.

```bash
lance list
```

### `lance modules`

List all available attack modules with OWASP/MITRE refs and probe counts.

```bash
lance modules
```

### `lance check`

Test connectivity to configured LLM providers.

```bash
lance check            # Test all providers
lance check openai     # Test specific provider
lance check ollama
lance check anthropic
```

### `lance ui`

Launch the self-hosted Web UI dashboard.

```bash
lance ui                    # http://localhost:7777
lance ui --port 8080        # Custom port
lance ui --host 0.0.0.0     # Expose to local network
```

### `lance serve`

Start the headless REST API server (no web interface).

```bash
lance serve
lance serve --host 0.0.0.0 --port 8000
```

### `lance run` *(v0.6.0)*

Run a full multi-target assessment from a YAML config file.

```bash
lance run config.yaml
lance run config.yaml --output results/
lance run config.yaml --dry-run
lance run config.yaml --fail-on 7.0
```

See `lance/config_runner/example_config.yaml` for full config reference.

### `lance chain` *(v0.6.0)*

Run a multi-turn conversation attack chain against a model.

```bash
lance chain ollama/llama3 --chain-type crescendo
lance chain ollama/llama3 --chain-type persona_anchoring
lance chain openai/gpt-4o --chain-type linear_jailbreak --system-prompt "You are helpful."
lance chain ollama/llama3 --chain ./my_custom_chain.yaml
```

Built-in chain types: `persona_anchoring`, `crescendo`, `context_poisoning`, `memory_exploitation`, `jailbreak_escalation`, `linear_jailbreak`

### `lance guardrail` *(v0.6.0)*

Re-fire confirmed findings from a campaign to verify they are remediated.

```bash
lance guardrail a1b2c3d4
lance guardrail a1b2c3d4 --system-prompt-file ./prompts/fixed.txt
lance guardrail a1b2c3d4 --retries 5
```

---

## Web UI

LANCE v0.5.0 ships a full self-hosted Web UI. No React. No Node build step. No external dependencies beyond the Python install.

```bash
lance ui
# Launches at http://localhost:7777 and opens your browser automatically
```

### Dashboard

- All campaigns with status badge, risk score, finding count, and date
- Risk score trend line chart across completed scans
- Search and filter by model name or campaign name
- One-click campaign delete

### New Scan Page

- Model input with preset buttons for common providers (ollama/llama3, openai/gpt-4o, claude, etc.)
- Module selector — individual checkboxes or select-all
- System prompt textarea
- Launch overlay with live WebSocket progress bar while scan runs

### Campaign Detail Page

- Risk score with HIGH / MEDIUM / LOW classification
- Live scan progress bar (WebSocket — updates in real time during active scans, reloads on completion)
- **Four charts:** severity doughnut, module hits vs blocked bar, probe outcomes doughnut, OWASP LLM Top 10 radar
- Findings table with per-severity filter
- Expandable drawer per finding: exact probe payload, model response, OWASP + MITRE references, CVSS score, remediation guidance

---

## Reports

### Campaign Report Contents

**Cover page**
- Target model, risk score, severity classification
- Campaign metadata: date, probe count, assessor, organisation

**Executive Summary**
- Risk score with contextual interpretation
- Finding count by severity (Critical / High / Medium / Low)
- Module coverage overview

**Charts**
- Severity distribution
- Attack success rate by module (hits vs blocked)
- Overall probe outcomes (hits / blocked / miss / error)
- OWASP LLM Top 10 exposure radar

**Findings — per finding**
- Severity, title, description
- OWASP LLM Top 10 + MITRE ATLAS references
- CVSS score
- Exact probe payload that triggered the finding
- Exact model response that confirmed it
- Remediation guidance

**Framework Coverage Map**
- OWASP LLM Top 10 — which categories were tested, which had confirmed findings
- MITRE ATLAS v4.5 — technique-level mapping

### Generating Reports

```bash
# HTML (default — no system dependencies required)
lance scan openai/gpt-4o
# Auto-named: lance_report_openai_gpt-4o_a1b2c3d4_20250315_143022.html

# PDF output
lance scan openai/gpt-4o --output report.pdf

# Custom path
lance scan openai/gpt-4o --output /reports/q1-assessment.html

# Regenerate report from existing campaign
lance report a1b2c3d4 --output reassessment.pdf

# Multi-model comparison
lance compare openai/gpt-4o openai/gpt-4o-mini --output comparison.html
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values.

```bash
cp .env.example .env
```

### Full Configuration Reference

```env
# ── LLM Provider Keys ──────────────────────────────────────────────────────
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Ollama runs locally — no key needed
OLLAMA_BASE_URL=http://localhost:11434

# ── Judge Model ────────────────────────────────────────────────────────────
# The LLM used to score attack responses.
# ollama/llama3       → free, local, no API cost (default)
# openai/gpt-4o-mini  → higher accuracy, ~$0.0001 per probe
JUDGE_MODEL=ollama/llama3

# ── Database ───────────────────────────────────────────────────────────────
DATABASE_URL=sqlite:///./lance.db
# PostgreSQL:
# DATABASE_URL=postgresql://user:pass@host:5432/lance

# ── Performance ────────────────────────────────────────────────────────────
MAX_CONCURRENT_PROBES=5         # Async concurrency limit
PROBE_TIMEOUT_SECONDS=30        # Per-probe timeout

# ── Report Branding ────────────────────────────────────────────────────────
ORG_NAME=iosec.in
ASSESSOR_NAME=Shekhar Suman

# ── API Server ─────────────────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000
```

---

## Provider Setup

### Ollama (Local — Recommended Starting Point)

Free. No API key. Runs entirely on your machine.

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3
ollama pull mistral

# Scan
lance scan ollama/llama3 --modules all
```

### OpenAI

```bash
# .env
OPENAI_API_KEY=sk-...

# Scan
lance scan openai/gpt-4o
lance scan openai/gpt-4o-mini
```

### Anthropic

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...

# Scan
lance scan anthropic/claude-haiku-4-5-20251001
lance scan anthropic/claude-sonnet-4-6
```

### Azure OpenAI

```bash
# .env
AZURE_API_KEY=...
AZURE_API_BASE=https://your-resource.openai.azure.com/
AZURE_API_VERSION=2024-02-01

# Scan
lance scan azure/your-deployment-name
```

### Amazon Bedrock

```bash
# Uses AWS credentials from environment or ~/.aws/credentials
lance scan bedrock/anthropic.claude-3-haiku-20240307-v1:0
```

---

## CICD Integration

LANCE can gate pipelines on risk score. When `--fail-on` is set, the process exits with code 1 if the scan produces a score at or above the threshold.

### GitHub Actions

```yaml
name: LLM Red Team

on:
  push:
    branches: [main]
  pull_request:

jobs:
  lance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install LANCE
        run: pip install lance-llm

      - name: Run red team scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          lance scan openai/gpt-4o-mini \
            --modules all \
            --system-prompt-file ./prompts/system.txt \
            --output lance_report.html \
            --fail-on 7.0

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: lance-report
          path: lance_report.html
```

### Recommended Thresholds

| `--fail-on` | Use case |
|---|---|
| `9.0` | Block only critical-risk models |
| `7.0` | Block high-risk and above (recommended for production gates) |
| `4.0` | Block medium-risk and above (strict — pre-release) |

---

## REST API

Available at `http://localhost:8000` (`lance serve`) or `http://localhost:7777` (`lance ui`).

Interactive Swagger docs: `/api/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check + version |
| `GET` | `/api/campaigns` | List all campaigns |
| `POST` | `/api/campaigns` | Create a campaign |
| `GET` | `/api/campaigns/{id}` | Campaign detail |
| `POST` | `/api/campaigns/{id}/run` | Execute campaign (background) |
| `GET` | `/api/campaigns/{id}/progress` | Poll live progress |
| `DELETE` | `/api/campaigns/{id}` | Delete campaign + findings |
| `GET` | `/api/findings` | List all findings |
| `GET` | `/api/reports/{id}` | Render HTML report |
| `GET` | `/api/system/modules` | List attack modules |
| `WS` | `/ws/{campaign_id}` | Live progress WebSocket |

### Quick API Example

```bash
# Create
curl -X POST http://localhost:8000/api/campaigns \
  -H "Content-Type: application/json" \
  -d '{"name":"gpt-4o assessment","target_model":"openai/gpt-4o","attack_modules":["prompt_injection","jailbreak"]}'

# Run
curl -X POST http://localhost:8000/api/campaigns/{id}/run

# Poll
curl http://localhost:8000/api/campaigns/{id}/progress
```

---

## Docker

```bash
# Build
docker build -t lance .

# Run a scan
docker run --rm \
  -e OPENAI_API_KEY=sk-... \
  -v $(pwd)/reports:/app/reports \
  lance scan openai/gpt-4o --modules all

# Web UI via compose
docker-compose up
# http://localhost:7777
```

---

## Roadmap

| Version | Feature | Status |
|---|---|---|
| v0.4.0 | CLI · 5 modules · 195+ probes · HTML + PDF reports | ✅ Released |
| v0.5.0 | Web UI · WebSocket live progress · Campaign history | ✅ Released |
| v0.6.0 | 4 safety modules · Multi-turn chains · Custom vulns · Guardrails · YAML runner | ✅ Released |
| v1.0.0 | Custom judge model fine-tuning · Full release | 🔨 In Progress |

### v0.6.0 — Released

**4 new safety modules** — Bias (gender/race/political/religion), PII Leakage (direct/session/database), Toxicity (profanity/insults/threats/harassment), Misinformation (factual errors/unsupported claims/deepfake content). Total: 9 modules, 475+ probes.

**19 mutation strategies** — adds Leetspeak, ROT-13, Math Problem framing, Base64 double, ASCII hex, Crescendo, Linear, Tree branch to the original 10.

**Multi-turn chains** — 6 built-in YAML chain templates. `lance chain ollama/llama3 --chain-type crescendo`

**Custom Vulnerability API** — define your own in 5 lines:
```python
from lance.attacks.custom import CustomVulnerability
vuln = CustomVulnerability(
    name="Business Logic",
    criteria="The system should not allow privilege escalation.",
    types=["access_control", "privilege_escalation"],
)
```

**YAML config runner** — `lance run config.yaml` for multi-target batch assessments.

**Guardrails** — `lance guardrail <campaign_id>` to verify remediations.

**NIST AI RMF mapping** — all safety modules include GOVERN + MAP + MANAGE references.

### v1.0.0 — Custom Judge Fine-Tuning *(In Progress)*

Fine-tune your own judge model on LANCE's labelled probe/response dataset, or on your organisation's own reviewed findings. Run locally via Ollama — free, fully private, with accuracy metrics against a held-out test set.

---

## Contributing

```bash
git clone https://github.com/iosec-in/lance.git
cd lance
poetry install && poetry shell

# Run tests
pytest tests/

# Lint
ruff check lance/
```

### Adding a Custom Attack Module

Each module lives in `lance/attacks/<module_name>/`:

```
lance/attacks/my_module/
├── __init__.py
├── module.py       # build_probes() and get_module_info()
└── payloads.yaml   # seed payloads
```

### Adding Custom Payloads

Add seeds directly to any existing `payloads.yaml`. No code changes required.

---

## License

MIT. See [LICENSE](LICENSE).

---

## About

Built by [Shekhar Suman](https://iosec.in) — 14 years in offensive security, OSCP, GSLC, CSSLP.

LANCE started as a tool to fill a gap that kept appearing: teams deploying LLMs into production with no structured adversarial evaluation and no artefact to show for the security work they had done. It is open source because the problem will not be solved by tools available only to well-funded organisations.

The goal is for *"we ran LANCE before we shipped"* to become standard practice.

---

<div align="center">

**[⭐ Star on GitHub](https://github.com/iosec-in/lance)** — helps the project get discovered by the teams that need it

[lance.iosec.in](https://lance.iosec.in) · [iosec.in](https://iosec.in) · [@callmeshekhu](https://twitter.com/callmeshekhu)

*Precision strikes. Zero false calm.*

</div>
