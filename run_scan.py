"""
LANCE — Direct scan runner (bypasses CLI)
Usage: python run_scan.py
"""
import asyncio
from lance.db.models import init_db, SessionLocal
from lance.engine.orchestrator import create_campaign, run_campaign
from rich.console import Console

console = Console()

# ── CONFIGURE YOUR SCAN HERE ──────────────────────────────────────────────────
TARGET_MODEL = "ollama/llama3"
CAMPAIGN_NAME = "llama3-first-scan"
SYSTEM_PROMPT = None  # or paste a system prompt string here
ATTACK_MODULES = ["prompt_injection"]
# ─────────────────────────────────────────────────────────────────────────────


async def main():
    init_db()
    db = SessionLocal()

    try:
        console.print(f"\n[bold green]🐍 LANCE[/bold green] — firing scan against [bold]{TARGET_MODEL}[/bold]\n")

        campaign = create_campaign(
            db=db,
            name=CAMPAIGN_NAME,
            target_model=TARGET_MODEL,
            attack_modules=ATTACK_MODULES,
            target_system_prompt=SYSTEM_PROMPT,
        )

        console.print(f"[dim]Campaign ID: {campaign.id}[/dim]")

        async def progress(current, total, message):
            console.print(f"  [{current}/{total}] {message}")

        campaign = await run_campaign(campaign.id, db, progress_callback=progress)

        console.print(f"\n[bold]── RESULTS ──[/bold]")
        console.print(f"Risk Score:        [bold red]{campaign.risk_score}/10[/bold red]")
        console.print(f"Total probes:      {campaign.total_probes}")
        console.print(f"Successful attacks:[red] {campaign.successful_attacks}[/red]")
        console.print(f"Blocked:           [green]{campaign.failed_attacks}[/green]")
        console.print(f"\n[dim]Campaign ID: {campaign.id}[/dim]")
        console.print(f"[dim]Run 'lance serve' to view dashboard[/dim]\n")

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
