"""
LANCE Config Runner (v0.6.0)
Run full red team campaigns from a YAML config file.

Usage:
    lance run config.yaml
    lance run config.yaml --output results/
    lance run config.yaml --dry-run

Config format:
    See lance/config_runner/example_config.yaml
"""
from __future__ import annotations
import asyncio
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class ScanTarget:
    model:         str
    purpose:       str         = ""
    system_prompt: str         = ""
    system_prompt_file: str    = ""


@dataclass
class RunConfig:
    targets:            list[ScanTarget]
    modules:            list[str]           = field(default_factory=lambda: ["all"])
    chain_templates:    list[str]           = field(default_factory=list)
    custom_vulns:       list[str]           = field(default_factory=list)
    max_concurrent:     int                 = 5
    attacks_per_module: int                 = 1
    fail_on:            Optional[float]     = None
    output_folder:      str                 = "results"
    run_guardrails:     bool                = False
    guardrail_retries:  int                 = 3
    judge_model:        Optional[str]       = None
    report_format:      str                 = "html"    # html | pdf | both
    name:               str                 = "LANCE Run"


def load_config(path: str) -> RunConfig:
    """Load a RunConfig from a YAML file."""
    data = yaml.safe_load(Path(path).read_text())

    targets = []
    for t in data.get("targets", []):
        sp      = t.get("system_prompt", "")
        sp_file = t.get("system_prompt_file", "")
        if sp_file:
            sp_path = Path(sp_file)
            if sp_path.exists():
                sp = sp_path.read_text()
        targets.append(ScanTarget(
            model=t["model"],
            purpose=t.get("purpose", ""),
            system_prompt=sp,
            system_prompt_file=sp_file,
        ))

    return RunConfig(
        targets=targets,
        modules=data.get("modules", ["all"]),
        chain_templates=data.get("chain_templates", []),
        custom_vulns=data.get("custom_vulns", []),
        max_concurrent=data.get("max_concurrent", 5),
        attacks_per_module=data.get("attacks_per_module", 1),
        fail_on=data.get("fail_on"),
        output_folder=data.get("output_folder", "results"),
        run_guardrails=data.get("run_guardrails", False),
        guardrail_retries=data.get("guardrail_retries", 3),
        judge_model=data.get("judge_model"),
        report_format=data.get("report_format", "html"),
        name=data.get("name", "LANCE Run"),
    )


async def execute_config(config: RunConfig, dry_run: bool = False) -> dict:
    """Execute a full RunConfig. Returns summary dict."""
    from lance.attacks.module_factory import get_all_modules, get_module
    from pathlib import Path

    Path(config.output_folder).mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold blue]LANCE[/bold blue] — {config.name}")
    console.print(f"Targets: {len(config.targets)} · Modules: {config.modules}\n")

    results = []

    for target in config.targets:
        console.print(f"[cyan]→ Scanning:[/cyan] {target.model}")
        if dry_run:
            console.print(f"  [yellow][DRY RUN][/yellow] Skipping actual scan for {target.model}")
            results.append({
                "model":      target.model,
                "risk_score": 0.0,
                "status":     "dry_run",
            })
            continue

        # Resolve modules
        if config.modules == ["all"]:
            module_names = list(get_all_modules().keys())
        else:
            module_names = config.modules

        # Build system prompt
        sp = target.system_prompt

        # Run scan (delegated to orchestrator)
        try:
            from lance.engine.orchestrator import Orchestrator
            orchestrator = Orchestrator()
            result = await orchestrator.run(
                model=target.model,
                modules=module_names,
                system_prompt=sp or None,
                max_concurrent=config.max_concurrent,
            )
            results.append({
                "model":      target.model,
                "risk_score": result.get("risk_score", 0.0),
                "findings":   result.get("findings", []),
                "status":     "complete",
            })
            console.print(f"  [green]✓[/green] Risk score: {result.get('risk_score', 0.0):.1f}/10")
        except Exception as e:
            console.print(f"  [red]✗[/red] Error: {e}")
            results.append({
                "model":  target.model,
                "status": "error",
                "error":  str(e),
            })

    # Summary table
    table = Table(title="Run Summary", show_header=True)
    table.add_column("Model",       style="cyan")
    table.add_column("Risk Score",  justify="right")
    table.add_column("Status",      justify="center")

    max_score = 0.0
    for r in results:
        score = r.get("risk_score", 0.0)
        max_score = max(max_score, score)
        status_str = "[green]PASS[/green]" if r["status"] == "complete" else f"[yellow]{r['status']}[/yellow]"
        table.add_row(r["model"], f"{score:.1f}", status_str)

    console.print(table)

    # Fail-on check
    if config.fail_on is not None and max_score >= config.fail_on:
        console.print(f"\n[bold red]FAIL:[/bold red] Max risk score {max_score:.1f} exceeds threshold {config.fail_on}")
        return {"results": results, "exit_code": 1, "max_score": max_score}

    return {"results": results, "exit_code": 0, "max_score": max_score}
