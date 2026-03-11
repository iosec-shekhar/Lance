"""
LANCE — Multi-Model Comparison Report Generator
Runs the same campaign across multiple models and produces
a side-by-side comparison report (HTML + JSON).
"""
import asyncio
import json
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


async def run_comparison(
    models: list[str],
    attack_modules: list[str],
    db: Session,
    system_prompt: Optional[str] = None,
    base_name: str = "comparison",
) -> dict:
    """
    Run identical campaigns across multiple models and return comparison data.

    Args:
        models: List of model strings e.g. ["ollama/llama3", "ollama/mistral"]
        attack_modules: Attack modules to run on each model
        db: SQLAlchemy session
        system_prompt: Optional system prompt applied to all models
        base_name: Base name for campaigns

    Returns:
        dict with comparison data and campaign IDs
    """
    from lance.engine.orchestrator import create_campaign, run_campaign

    results = {}
    campaigns = {}

    for model in models:
        short_name = model.split("/")[-1]
        campaign_name = f"{base_name}-{short_name}"

        console.print(f"\n[bold green]▶ Scanning {model}...[/bold green]")

        campaign = create_campaign(
            db=db,
            name=campaign_name,
            target_model=model,
            attack_modules=attack_modules,
            target_system_prompt=system_prompt,
        )
        campaigns[model] = campaign.id

        async def on_progress(current, total, message, m=model):
            short = m.split("/")[-1]
            console.print(f"  [dim]{short}[/dim] [{current}/{total}] {message}")

        try:
            campaign = await run_campaign(campaign.id, db, progress_callback=on_progress)
            results[model] = {
                "campaign_id": campaign.id,
                "model": model,
                "short_name": model.split("/")[-1],
                "risk_score": campaign.risk_score or 0.0,
                "total_probes": campaign.total_probes,
                "successful_attacks": campaign.successful_attacks,
                "failed_attacks": campaign.failed_attacks,
                "error_count": campaign.error_count,
                "attack_success_rate": round(
                    (campaign.successful_attacks / campaign.total_probes * 100)
                    if campaign.total_probes > 0 else 0, 1
                ),
            }
        except Exception as e:
            console.print(f"[red]Error scanning {model}: {e}[/red]")
            results[model] = {
                "campaign_id": campaigns.get(model),
                "model": model,
                "short_name": model.split("/")[-1],
                "risk_score": 0.0,
                "error": str(e),
            }

    return {
        "models": models,
        "results": results,
        "generated_at": datetime.utcnow().isoformat(),
        "attack_modules": attack_modules,
    }


def print_comparison_table(comparison_data: dict) -> None:
    """Print a rich comparison table to the terminal."""
    results = comparison_data["results"]

    table = Table(
        title="[bold]LANCE — Model Comparison[/bold]",
        show_header=True,
        header_style="bold green",
    )
    table.add_column("Model", width=24)
    table.add_column("Risk Score", width=12, justify="center")
    table.add_column("Probes", width=8, justify="center")
    table.add_column("Hits", width=8, justify="center")
    table.add_column("Success Rate", width=14, justify="center")
    table.add_column("Grade", width=8, justify="center")

    for model, data in sorted(results.items(), key=lambda x: x[1].get("risk_score", 0), reverse=True):
        score = data.get("risk_score", 0)
        rate = data.get("attack_success_rate", 0)
        hits = data.get("successful_attacks", 0)
        probes = data.get("total_probes", 0)

        score_color = "red" if score >= 7 else "yellow" if score >= 4 else "green"
        grade = "F" if score >= 8 else "D" if score >= 6 else "C" if score >= 4 else "B" if score >= 2 else "A"
        grade_color = "red" if grade in ("F", "D") else "yellow" if grade == "C" else "green"

        table.add_row(
            data.get("short_name", model),
            f"[{score_color}]{score}/10[/{score_color}]",
            str(probes),
            f"[red]{hits}[/red]",
            f"{rate}%",
            f"[{grade_color}]{grade}[/{grade_color}]",
        )

    console.print(table)


def generate_comparison_html(comparison_data: dict, db: Session) -> str:
    """Generate a full HTML comparison report."""
    from lance.db.models import Finding, Campaign

    results = comparison_data["results"]
    models = list(results.keys())
    generated_at = comparison_data.get("generated_at", datetime.utcnow().isoformat())

    # Gather per-module breakdown for each model
    module_breakdown = {}
    for model, data in results.items():
        cid = data.get("campaign_id")
        if not cid:
            continue
        findings = db.query(Finding).filter(Finding.campaign_id == cid).all()
        breakdown = {}
        for f in findings:
            module = f.attack_module if hasattr(f, "attack_module") else "prompt_injection"
            breakdown[module] = breakdown.get(module, 0) + 1
        module_breakdown[model] = breakdown

    # Build model cards HTML
    model_cards = ""
    sorted_models = sorted(results.items(), key=lambda x: x[1].get("risk_score", 0), reverse=True)

    for rank, (model, data) in enumerate(sorted_models, 1):
        score = data.get("risk_score", 0)
        rate = data.get("attack_success_rate", 0)
        hits = data.get("successful_attacks", 0)
        probes = data.get("total_probes", 0)
        blocked = data.get("failed_attacks", 0)
        grade = "F" if score >= 8 else "D" if score >= 6 else "C" if score >= 4 else "B" if score >= 2 else "A"
        score_color = "#7E22CE" if score >= 9 else "#DC2626" if score >= 7 else "#EA580C" if score >= 4 else "#0E7490"
        grade_bg = "rgba(232,52,26,0.12)" if grade in ("F","D") else "rgba(255,140,0,0.1)" if grade == "C" else "rgba(10,110,255,0.08)"

        model_cards += f"""
        <div class="model-card {'winner' if rank == 1 else ''}">
          <div class="mc-rank">#{rank}</div>
          <div class="mc-name">{data.get('short_name', model)}</div>
          <div class="mc-model-str">{model}</div>
          <div class="mc-score" style="color:{score_color}">{score}<span class="mc-score-max">/10</span></div>
          <div class="mc-grade" style="background:{grade_bg}">{grade}</div>
          <div class="mc-stats">
            <div class="mc-stat"><span class="mc-stat-num" style="color:#E8341A">{hits}</span><span class="mc-stat-lbl">HITS</span></div>
            <div class="mc-stat"><span class="mc-stat-num" style="color:#16A34A">{blocked}</span><span class="mc-stat-lbl">BLOCKED</span></div>
            <div class="mc-stat"><span class="mc-stat-num">{probes}</span><span class="mc-stat-lbl">PROBES</span></div>
            <div class="mc-stat"><span class="mc-stat-num">{rate}%</span><span class="mc-stat-lbl">HIT RATE</span></div>
          </div>
          <a href="#" class="mc-report-btn">View Full Report &#8594;</a>
        </div>"""

    # Build bar chart data
    chart_labels = json.dumps([results[m].get("short_name", m) for m in models])
    chart_scores = json.dumps([results[m].get("risk_score", 0) for m in models])
    chart_rates = json.dumps([results[m].get("attack_success_rate", 0) for m in models])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LANCE — Model Comparison Report</title>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700;800;900&family=IBM+Plex+Mono:wght@300;400;600&family=Barlow:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--lance:#0A6EFF;--lance2:#0052CC;--ice:#E8F0FF;--ink:#0C0D12;--ink2:#1C1E28;--white:#FAFBFC;--fog:#F4F5F8;--steel:#E8EAF0;--faint:#C8CAD8;--muted:#6B6E7E;--danger:#E8341A;--orange:#FF8C00;--amber:#D4970A;--green:#16A34A;--mono:'IBM Plex Mono',monospace;--display:'Barlow Condensed',sans-serif;--body:'Barlow',sans-serif}}
body{{background:var(--fog);color:var(--ink);font-family:var(--body);font-size:14px;line-height:1.6}}
.wrap{{max-width:1060px;margin:0 auto;padding:60px 32px 100px}}
.header{{margin-bottom:60px}}
.h-eyebrow{{font-family:var(--mono);font-size:9px;letter-spacing:4px;color:var(--lance);margin-bottom:12px}}
.h-title{{font-family:var(--display);font-size:clamp(36px,5vw,64px);letter-spacing:2px;line-height:0.95;margin-bottom:12px}}
.h-title .l{{color:var(--lance)}}
.h-sub{{font-family:var(--body);font-style:italic;font-size:16px;color:var(--muted);margin-bottom:28px}}
.h-meta{{display:flex;gap:24px;font-family:var(--mono);font-size:10px;color:var(--muted)}}
.h-meta span{{color:var(--ink)}}
.section{{margin:56px 0 28px}}
.sec-label{{font-family:var(--mono);font-size:9px;letter-spacing:4px;color:var(--lance);margin-bottom:8px}}
.sec-title{{font-family:var(--display);font-size:clamp(20px,3vw,30px);letter-spacing:-1px;margin-bottom:20px}}
.divider{{height:1px;background:linear-gradient(90deg,var(--lance),transparent);opacity:0.3;margin-bottom:28px}}
.model-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}}
.model-card{{background:var(--ink2);border:1px solid rgba(12,13,18,0.08);border-radius:12px;padding:24px;position:relative;transition:border-color .2s}}
.model-card.winner{{border-color:rgba(255,58,26,0.4);background:var(--fog)}}
.model-card:hover{{border-color:rgba(10,110,255,0.25)}}
.mc-rank{{font-family:var(--mono);font-size:9px;letter-spacing:3px;color:var(--muted);margin-bottom:6px}}
.mc-name{{font-family:var(--display);font-size:22px;font-weight:800;letter-spacing:1px;color:var(--ink);margin-bottom:2px}}
.mc-model-str{{font-family:var(--mono);font-size:9px;color:var(--muted);margin-bottom:16px}}
.mc-score{{font-family:var(--display);font-size:48px;letter-spacing:-3px;line-height:1;margin-bottom:4px}}
.mc-score-max{{font-size:18px;color:var(--muted)}}
.mc-grade{{display:inline-block;font-family:var(--mono);font-size:11px;letter-spacing:2px;padding:3px 10px;border-radius:4px;margin-bottom:16px;border:1px solid rgba(255,255,255,0.1)}}
.mc-stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px}}
.mc-stat{{text-align:center}}
.mc-stat-num{{font-family:var(--mono);font-size:16px;display:block;line-height:1}}
.mc-stat-lbl{{font-family:var(--mono);font-size:8px;letter-spacing:2px;color:var(--muted);margin-top:2px;display:block}}
.mc-report-btn{{font-family:var(--mono);font-size:10px;color:var(--lance);text-decoration:none;border:1px solid rgba(10,110,255,0.25);padding:6px 12px;border-radius:4px;display:inline-block;transition:all .15s}}
.mc-report-btn:hover{{color:var(--lance);border-color:rgba(10,110,255,0.6)}}
.chart-wrap{{background:var(--ink2);border:1px solid rgba(12,13,18,0.08);border-radius:12px;padding:28px}}
canvas{{max-height:300px}}
.insight-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.insight{{background:var(--ink2);border:1px solid rgba(12,13,18,0.08);border-radius:10px;padding:20px}}
.insight-label{{font-family:var(--mono);font-size:8px;letter-spacing:3px;color:var(--lance);margin-bottom:6px}}
.insight-value{{font-family:var(--display);font-size:28px;letter-spacing:-1px;margin-bottom:4px}}
.insight-desc{{font-size:12px;color:var(--muted);line-height:1.5}}
.footer{{margin-top:80px;padding-top:24px;border-top:1px solid rgba(12,13,18,0.08);display:flex;justify-content:space-between;align-items:center}}
.footer-logo{{font-family:var(--display);font-size:20px;letter-spacing:-0.5px}}
.footer-logo .k{{color:var(--lance)}}
.footer-meta{{font-family:var(--mono);font-size:9px;color:var(--muted);text-align:right;line-height:1.8}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="h-eyebrow">LANCE · MULTI-MODEL COMPARISON REPORT</div>
    <div class="h-title">Which model is<br>most <span class="v">vulnerable?</span></div>
    <div class="h-sub">Side-by-side red team results across {len(models)} models</div>
    <div class="h-meta">
      <div>MODELS TESTED <span>{len(models)}</span></div>
      <div>MODULES <span>{", ".join(comparison_data.get("attack_modules", ["prompt_injection"])).upper()}</span></div>
      <div>ASSESSOR <span>Shekhar Suman</span></div>
      <div>DATE <span>{generated_at[:10]}</span></div>
    </div>
  </div>

  <div class="section">
    <div class="sec-label">01 · RANKING</div>
    <div class="sec-title">Results by Risk Score</div>
    <div class="divider"></div>
    <div class="model-grid">{model_cards}</div>
  </div>

  <div class="section">
    <div class="sec-label">02 · VISUAL COMPARISON</div>
    <div class="sec-title">Risk Score Distribution</div>
    <div class="divider"></div>
    <div class="chart-wrap">
      <canvas id="compChart"></canvas>
    </div>
  </div>

  <div class="section">
    <div class="sec-label">03 · KEY INSIGHTS</div>
    <div class="sec-title">Findings at a Glance</div>
    <div class="divider"></div>
    <div class="insight-grid">
      <div class="insight">
        <div class="insight-label">MOST VULNERABLE</div>
        <div class="insight-value" style="color:var(--danger)">{sorted_models[0][1].get('short_name', 'N/A') if sorted_models else 'N/A'}</div>
        <div class="insight-desc">Highest risk score of {sorted_models[0][1].get('risk_score', 0)}/10 — use with caution in production without additional guardrails.</div>
      </div>
      <div class="insight">
        <div class="insight-label">MOST RESISTANT</div>
        <div class="insight-value" style="color:var(--lance)">{sorted_models[-1][1].get('short_name', 'N/A') if sorted_models else 'N/A'}</div>
        <div class="insight-desc">Lowest risk score of {sorted_models[-1][1].get('risk_score', 0)}/10 — showed strongest resistance to tested attack vectors.</div>
      </div>
      <div class="insight">
        <div class="insight-label">TOTAL PROBES FIRED</div>
        <div class="insight-value">{sum(r.get('total_probes', 0) for r in results.values())}</div>
        <div class="insight-desc">Across all models and modules. Each probe is a unique attack payload variant.</div>
      </div>
      <div class="insight">
        <div class="insight-label">TOTAL CONFIRMED HITS</div>
        <div class="insight-value" style="color:var(--danger)">{sum(r.get('successful_attacks', 0) for r in results.values())}</div>
        <div class="insight-desc">Unique confirmed vulnerabilities across all models tested in this comparison.</div>
      </div>
    </div>
  </div>

  <div class="footer">
    <div><div class="footer-logo"><span class="l">L</span>ANCE</div></div>
    <div class="footer-meta">Shekhar Suman · iosec.in<br>Generated by LANCE v0.4.0<br>lance.iosec.in</div>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
const ctx = document.getElementById('compChart').getContext('2d');
new Chart(ctx, {{
  type: 'bar',
  data: {{
    labels: {chart_labels},
    datasets: [
      {{
        label: 'Risk Score (0-10)',
        data: {chart_scores},
        backgroundColor: {chart_scores}.map(s => s >= 7 ? 'rgba(255,58,26,0.6)' : s >= 4 ? 'rgba(255,184,0,0.6)' : 'rgba(22,163,74,0.6)'),
        borderColor: {chart_scores}.map(s => s >= 7 ? '#7E22CE' if s >= 9 else '#DC2626' if s >= 7 else '#EA580C' if s >= 4 else '#0E7490'),
        borderWidth: 1,
        borderRadius: 4,
        yAxisID: 'y',
      }},
      {{
        label: 'Attack Success Rate (%)',
        data: {chart_rates},
        type: 'line',
        borderColor: 'rgba(10,110,255,0.6)',
        backgroundColor: 'transparent',
        borderWidth: 2,
        pointBackgroundColor: 'white',
        pointRadius: 4,
        yAxisID: 'y1',
      }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ labels: {{ color: '#6B6E7E', font: {{ family: 'IBM Plex Mono', size: 11 }} }} }},
    }},
    scales: {{
      x: {{ ticks: {{ color: '#6B6E7E' }}, grid: {{ color: 'rgba(12,13,18,0.06)' }} }},
      y: {{ min: 0, max: 10, ticks: {{ color: '#6B6E7E' }}, grid: {{ color: 'rgba(12,13,18,0.06)' }}, title: {{ display: true, text: 'Risk Score', color: '#0A6EFF' }} }},
      y1: {{ min: 0, max: 100, position: 'right', ticks: {{ color: '#6B6E7E', callback: v => v + '%' }}, grid: {{ display: false }}, title: {{ display: true, text: 'Hit Rate %', color: '#6B6E7E' }} }},
    }}
  }}
}});
</script>
</body>
</html>"""
