"""
LANCE — Command Line Interface
lance.iosec.in
"""
import asyncio
import os
from datetime import datetime
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.prompt import Prompt
from rich.columns import Columns
from rich import box

console = Console()

# ── Severity colour palette (#10) ──────────────────────────────
SEV_COLOURS = {
    "critical": "bold magenta",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "bold cyan",
}

# ── Module display names (#5) ──────────────────────────────────
MODULE_DISPLAY = {
    "prompt_injection":  "Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "jailbreak":         "Jailbreak",
    "model_dos":         "Model DoS",
    "rag_poisoning":     "RAG Poisoning",
    "bias":              "Bias",
    "pii_leakage":       "PII Leakage",
    "toxicity":          "Toxicity",
    "misinformation":    "Misinformation",
}

def fmt_module(name: str) -> str:
    """Return human-readable module name — no underscores."""
    return MODULE_DISPLAY.get(name, name.replace("_", " ").title())

def fmt_modules(module_list) -> str:
    return ", ".join(fmt_module(m) for m in module_list)


# ── Banner (#9) ─────────────────────────────────────────────────
def print_banner():
    console.print()
    # Lance tip icon in blue
    icon = (
        "[bold blue]  ◁━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◆[/bold blue]"
    )
    wordmark = (
        "  [bold white]L[/bold white]"
        "[bold blue]A[/bold blue]"
        "[bold white]N[/bold white]"
        "[bold blue]C[/bold blue]"
        "[bold white]E[/bold white]"
    )
    console.print(icon)
    console.print(wordmark)
    console.print(
        "  [dim]LLM Adversarial Neural Component Evaluator[/dim]  "
        "[bold blue]·[/bold blue]  [bold blue]v0.6.0[/bold blue]  "
        "[bold blue]·[/bold blue]  [dim]lance.iosec.in[/dim]"
    )
    console.print("  [dim]" + "─" * 62 + "[/dim]")
    console.print("  [bold blue]precision strikes.[/bold blue]  [dim]zero false calm.[/dim]\n")


# ── Auto report naming (#2) ─────────────────────────────────────
def auto_report_name(model: str, campaign_id: str, ext: str = "html") -> str:
    """Generate a unique, non-overwriting report filename."""
    model_slug = model.replace("/", "_").replace(":", "-")
    id_short   = campaign_id[:8]
    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"lance_report_{model_slug}_{id_short}_{ts}.{ext}"


# ── Module selector helper (#1) ─────────────────────────────────
def resolve_modules(modules_arg: str) -> list:
    from lance.engine.orchestrator import ALL_MODULES
    raw = modules_arg.strip().lower()
    if raw == "all":
        return ALL_MODULES
    if raw == "pick":
        # Interactive picker
        console.print("\n[bold]Available attack modules:[/bold]")
        for i, m in enumerate(ALL_MODULES, 1):
            console.print(f"  [bold blue]{i}[/bold blue]. {fmt_module(m)}  [dim]({m})[/dim]")
        console.print()
        choice = Prompt.ask(
            "Enter module numbers or names (comma-separated, or [bold blue]all[/bold blue])",
            default="all"
        )
        if choice.strip().lower() == "all":
            return ALL_MODULES
        selected = []
        for token in choice.split(","):
            token = token.strip()
            if token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(ALL_MODULES):
                    selected.append(ALL_MODULES[idx])
            elif token in ALL_MODULES:
                selected.append(token)
            else:
                # try display name match
                for k, v in MODULE_DISPLAY.items():
                    if token.lower() in v.lower():
                        selected.append(k)
                        break
        return selected if selected else ALL_MODULES
    return [m.strip() for m in modules_arg.split(",")]


@click.group()
def app():
    """LANCE — LLM Adversarial Neural Component Evaluator"""
    pass


@app.command()
@click.argument("model")
@click.option("--name",               default=None,  help="Campaign name")
@click.option("--system-prompt",      default=None,  help="System prompt to test against")
@click.option("--system-prompt-file", default=None,  help="File containing system prompt")
@click.option("--modules",            default="all", help="Modules: 'all', 'pick' (interactive), or comma-separated names")
@click.option("--output",             default=None,  help="Report output path (.html or .pdf). Auto-named if omitted.")
def scan(model, name, system_prompt, system_prompt_file, modules, output):
    """Run a red team campaign. MODEL: ollama/llama3, openai/gpt-4o, etc."""
    print_banner()

    sp = system_prompt
    if system_prompt_file:
        try:
            with open(system_prompt_file) as f:
                sp = f.read().strip()
        except FileNotFoundError:
            console.print(f"[red]File not found: {system_prompt_file}[/red]")
            raise SystemExit(1)

    campaign_name = name or f"scan-{model.split('/')[-1]}"
    module_list   = resolve_modules(modules)

    console.print(Panel(
        f"[bold]Target:[/bold]   {model}\n"
        f"[bold]Campaign:[/bold] {campaign_name}\n"
        f"[bold]Modules:[/bold]  {fmt_modules(module_list)}\n"
        f"[bold]Prompt:[/bold]   {'[set]' if sp else '[none]'}",
        title="[bold blue]LANCE SCAN[/bold blue]",
        border_style="blue",
    ))

    asyncio.run(_run_scan(
        model=model,
        name=campaign_name,
        system_prompt=sp,
        module_list=module_list,
        output=output,
    ))


async def _run_scan(model, name, system_prompt, module_list, output):
    from lance.db.models import init_db, SessionLocal
    from lance.engine.orchestrator import create_campaign, run_campaign

    init_db()
    db = SessionLocal()

    try:
        campaign = create_campaign(
            db=db,
            name=name,
            target_model=model,
            attack_modules=module_list,
            target_system_prompt=system_prompt,
        )
        # #3 — Campaign ID in readable cyan, not dim yellow
        console.print(f"[bold white]Campaign ID:[/bold white] [bold cyan]{campaign.id}[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Firing probes...", total=None)

            async def on_progress(current, total, message):
                progress.update(task, completed=current, total=total, description=message)

            campaign = await run_campaign(campaign.id, db, progress_callback=on_progress)

        _print_results(db, campaign)

        # #2 — Auto report naming if no output specified
        report_path = output or auto_report_name(model, campaign.id)
        _save_report(db, campaign.id, report_path)

    finally:
        db.close()


def _print_results(db, campaign):
    from lance.db.models import Finding

    findings  = db.query(Finding).filter(Finding.campaign_id == campaign.id).all()
    score     = campaign.risk_score or 0
    score_col = "red" if score >= 7 else "yellow" if score >= 4 else "green"

    console.print(f"\n[bold]{'─' * 50}[/bold]")
    console.print(f"Risk Score:  [{score_col}]{score:.1f}/10[/{score_col}]")
    console.print(f"Probes:      {campaign.total_probes}")
    console.print(f"Hits:        [red]{campaign.successful_attacks}[/red]")
    console.print(f"Blocked:     [green]{campaign.failed_attacks}[/green]")
    console.print(f"Errors:      [yellow]{campaign.error_count}[/yellow]")

    if findings:
        console.print(f"\n[bold red]FINDINGS ({len(findings)})[/bold red]")
        table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY)
        table.add_column("Severity", width=10)
        table.add_column("Title",    width=42)
        table.add_column("Module",   width=18)
        table.add_column("OWASP",    width=8)
        table.add_column("CVSS",     width=6)

        for f in findings:
            c = SEV_COLOURS.get(f.severity.value, "white")
            table.add_row(
                f"[{c}]{f.severity.value.upper()}[/{c}]",
                f.title,
                fmt_module(f.attack_module) if hasattr(f, "attack_module") else "—",
                f.owasp_ref or "—",
                str(f.cvss_score or "—"),
            )
        console.print(table)
    else:
        console.print("\n[bold green]No confirmed findings — model showed good resistance.[/bold green]")


def _save_report(db, campaign_id, output_path):
    from lance.db.models import Campaign, Finding, Probe
    from lance.api.routers.reports import render_report_html

    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    probes   = db.query(Probe).filter(Probe.campaign_id == campaign_id).all()
    html     = render_report_html(campaign, findings, probes)

    if output_path.endswith(".pdf"):
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(output_path)
            console.print(f"[green]PDF saved: {output_path}[/green]")
        except ImportError:
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w") as f:
                f.write(html)
            console.print(f"[yellow]WeasyPrint not installed — saved as HTML: {html_path}[/yellow]")
    else:
        with open(output_path, "w") as f:
            f.write(html)
        console.print(f"[bold green]Report saved:[/bold green] [cyan]{output_path}[/cyan]")


@app.command()
@click.argument("campaign_id")
@click.option("--output", default=None, help="Output path (.pdf or .html). Auto-named if omitted.")
def report(campaign_id, output):
    """Generate a report for a completed campaign."""
    from lance.db.models import init_db, SessionLocal, Campaign
    init_db()
    db = SessionLocal()
    try:
        # #2 — Auto-name if not specified
        if not output:
            campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
            model    = campaign.target_model if campaign else "unknown"
            output   = auto_report_name(model, campaign_id)
        _save_report(db, campaign_id, output)
        # #3 — Show the report hint with readable colours
        console.print(f"\n[dim]lance serve   → [/dim][bold cyan]http://localhost:8000[/bold cyan]")
    finally:
        db.close()


@app.command(name="list")
def list_campaigns():
    """List all campaigns."""
    from lance.db.models import init_db, SessionLocal, Campaign
    init_db()
    db = SessionLocal()
    try:
        campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).limit(20).all()
        if not campaigns:
            console.print("[dim]No campaigns yet. Run: lance scan ollama/llama3[/dim]")
            return
        table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY)
        table.add_column("ID",     width=10)
        table.add_column("Name",   width=28)
        table.add_column("Model",  width=28)
        table.add_column("Status", width=12)
        table.add_column("Hits",   width=6)
        table.add_column("Risk",   width=8)
        status_colors = {"completed": "green", "running": "yellow", "failed": "red", "pending": "dim"}
        for c in campaigns:
            sc = status_colors.get(c.status.value, "white")
            rc = "red" if (c.risk_score or 0) >= 7 else "yellow" if (c.risk_score or 0) >= 4 else "green"
            table.add_row(
                c.id[:8], c.name, c.target_model,
                f"[{sc}]{c.status.value}[/{sc}]",
                str(c.successful_attacks),
                f"[{rc}]{c.risk_score or '—'}[/{rc}]",
            )
        console.print(table)
    finally:
        db.close()


@app.command()
@click.option("--host",   default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
@click.option("--port",   default=7777,         help="Port to listen on (default: 7777)")
@click.option("--reload", is_flag=True,          help="Auto-reload on code changes (dev mode)")
def ui(host, port, reload):
    """Launch the LANCE Web UI dashboard.

    \b
    Opens a self-hosted web interface at http://localhost:7777
    All campaign data is stored locally in lance.db.

    \b
    Examples:
      lance ui
      lance ui --port 8080
      lance ui --host 0.0.0.0 --port 7777
    """
    print_banner()
    url = f"http://{'localhost' if host in ('0.0.0.0','127.0.0.1') else host}:{port}"
    console.print(f"[bold white]Web UI:[/bold white]    [bold cyan]{url}[/bold cyan]")
    console.print(f"[bold white]New scan:[/bold white]  [bold cyan]{url}/new[/bold cyan]")
    console.print(f"[dim]Ctrl+C to stop[/dim]\n")

    # Try to open browser automatically
    try:
        import webbrowser
        import threading
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    except Exception:
        pass

    import uvicorn
    from lance.db.models import init_db
    init_db()
    uvicorn.run(
        "lance.ui.server:ui_app",
        host=host, port=port,
        reload=reload,
        log_level="warning",
    )


@app.command()
@click.option("--host", default="0.0.0.0", help="API host")
@click.option("--port", default=8000, help="API port")
def serve(host, port):
    """Start the LANCE REST API server (headless, no UI).

    Use 'lance ui' to start the full web dashboard instead.
    """
    print_banner()
    console.print(f"[bold white]API:[/bold white]      [bold cyan]http://localhost:{port}/api[/bold cyan]")
    console.print(f"[bold white]API Docs:[/bold white] [bold cyan]http://localhost:{port}/api/docs[/bold cyan]")
    console.print(f"[dim]Ctrl+C to stop[/dim]\n")
    import uvicorn
    from lance.db.models import init_db
    init_db()
    uvicorn.run("lance.api.app:app", host=host, port=port, log_level="warning")


@app.command()
@click.argument("provider", default="all")
def check(provider):
    """Check connectivity. PROVIDER: openai | anthropic | ollama | all"""
    providers = ["openai", "anthropic", "ollama"] if provider == "all" else [provider]

    async def _check():
        from lance.engine.connectors.litellm_connector import check_provider_connectivity
        model_map = {
            "openai":    "openai/gpt-4o-mini",
            "anthropic": "anthropic/claude-haiku-4-5-20251001",
            "ollama":    "ollama/llama3",
        }
        for p in providers:
            m = model_map.get(p)
            if not m:
                console.print(f"[red]Unknown provider: {p}[/red]")
                continue
            console.print(f"Checking [bold]{p}[/bold] ({m})...", end=" ")
            result = await check_provider_connectivity(m)
            if result["reachable"]:
                console.print(f"[green]Connected[/green] ({result['latency_ms']}ms)")
            else:
                console.print(f"[red]Failed[/red] — {result['error']}")

    asyncio.run(_check())


@app.command()
def modules():
    """List available attack modules."""
    from lance.engine.orchestrator import list_available_modules
    print_banner()
    console.print("[bold]Available Attack Modules[/bold]\n")
    for m in list_available_modules():
        console.print(Panel(
            f"[dim]OWASP:[/dim] {m['owasp_ref']}  [dim]·[/dim]  "
            f"[dim]Seeds:[/dim] {m['seed_count']}  [dim]·[/dim]  "
            f"[dim]Probes:[/dim] {m['total_probes']}\n"
            f"[dim]{m['description']}[/dim]",
            title=f"[bold blue]{fmt_module(m['name'])}[/bold blue]",
            border_style="blue",
        ))
    console.print("\n[dim]Usage: lance scan ollama/llama3 --modules prompt_injection,jailbreak[/dim]")
    console.print("[dim]       lance scan ollama/llama3 --modules pick  (interactive)[/dim]\n")


@app.command()
@click.argument("models", nargs=-1, required=True)
@click.option("--name",          default="comparison", help="Base name for campaigns")
@click.option("--modules",       default="all",        help="Modules: 'all', 'pick', or comma-separated names")
@click.option("--output",        default=None,         help="Output path. Auto-named if omitted.")
@click.option("--system-prompt", default=None,         help="System prompt applied to all models")
def compare(models, name, modules, output, system_prompt):
    """Compare multiple models side-by-side.

    \b
    Example:
      lance compare ollama/llama3 ollama/mistral
      lance compare ollama/llama3 ollama/mistral --modules prompt_injection,jailbreak
      lance compare ollama/llama3 ollama/mistral --modules pick
    """
    print_banner()
    module_list = resolve_modules(modules)

    # #2 — Auto-name comparison report
    if not output:
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"lance_comparison_{ts}.html"

    console.print(Panel(
        f"[bold]Models:[/bold]   {', '.join(models)}\n"
        f"[bold]Modules:[/bold]  {fmt_modules(module_list)}\n"
        f"[bold]Output:[/bold]   {output}",
        title="[bold blue]LANCE COMPARISON[/bold blue]",
        border_style="blue",
    ))

    async def _run():
        from lance.db.models import init_db, SessionLocal
        from lance.reporting.comparison import run_comparison, print_comparison_table, generate_comparison_html
        init_db()
        db = SessionLocal()
        try:
            data = await run_comparison(
                models=list(models),
                attack_modules=module_list,
                db=db,
                system_prompt=system_prompt,
                base_name=name,
            )
            print_comparison_table(data)
            html = generate_comparison_html(data, db)
            with open(output, "w") as f:
                f.write(html)
            console.print(f"\n[bold green]Comparison report saved:[/bold green] [cyan]{output}[/cyan]")
        finally:
            db.close()

    asyncio.run(_run())




@app.command(name="run")
@click.argument("config_file")
@click.option("--output",    default=None,  help="Output folder override")
@click.option("--dry-run",   is_flag=True,  help="Validate config without running scans")
@click.option("--fail-on",   default=None,  type=float, help="Override fail_on threshold")
def run_config(config_file, output, dry_run, fail_on):
    """Run a full assessment from a YAML config file.

    \b
    Example:
      lance run config.yaml
      lance run config.yaml --output results/
      lance run config.yaml --dry-run
      lance run config.yaml --fail-on 7.0

    \b
    See lance/config_runner/example_config.yaml for config format.
    """
    print_banner()
    from lance.config_runner.runner import load_config, execute_config
    import sys

    try:
        config = load_config(config_file)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        raise SystemExit(1)

    if output:
        config.output_folder = output
    if fail_on is not None:
        config.fail_on = fail_on

    console.print(Panel(
        f"[bold]Config:[/bold]   {config_file}\n"
        f"[bold]Targets:[/bold]  {len(config.targets)}\n"
        f"[bold]Modules:[/bold]  {', '.join(config.modules)}\n"
        f"[bold]Output:[/bold]   {config.output_folder}\n"
        f"[bold]Fail-on:[/bold]  {config.fail_on or 'disabled'}",
        title="[bold blue]LANCE RUN[/bold blue]",
        border_style="blue",
    ))

    result = asyncio.run(execute_config(config, dry_run=dry_run))
    sys.exit(result.get("exit_code", 0))


@app.command()
@click.argument("campaign_id")
@click.option("--system-prompt",      default=None, help="Updated system prompt to test against")
@click.option("--system-prompt-file", default=None, help="File containing updated system prompt")
@click.option("--retries",            default=3,    help="Attempts per finding (default: 3)")
def guardrail(campaign_id, system_prompt, system_prompt_file, retries):
    """Re-fire findings from a campaign to verify they are remediated.

    \b
    Run after fixing a vulnerability to confirm the guardrail holds.

    \b
    Example:
      lance guardrail a1b2c3d4
      lance guardrail a1b2c3d4 --system-prompt-file ./prompts/fixed.txt
    """
    print_banner()

    sp = system_prompt
    if system_prompt_file:
        try:
            with open(system_prompt_file) as f:
                sp = f.read().strip()
        except FileNotFoundError:
            console.print(f"[red]File not found: {system_prompt_file}[/red]")
            raise SystemExit(1)

    async def _run():
        from lance.db.models import init_db, SessionLocal, Finding
        from lance.guardrails.engine import GuardrailEngine
        init_db()
        db = SessionLocal()
        try:
            findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
            if not findings:
                console.print(f"[yellow]No findings for campaign {campaign_id[:8]}[/yellow]")
                return

            console.print(f"Running guardrails on [bold]{len(findings)}[/bold] findings...
")
            engine  = GuardrailEngine(model="local", connector=None, judge=None)
            results = await engine.run_all(
                findings=[{
                    "id":        str(f.id),
                    "module":    f.attack_module if hasattr(f, "attack_module") else "unknown",
                    "payload":   f.payload or "",
                    "objective": f.description or "",
                    "owasp_ref": f.owasp_ref or "",
                    "mitre_ref": f.mitre_ref or "",
                } for f in findings],
                system_prompt=sp,
                retries=retries,
            )

            summary = engine.summary(results)
            table = Table(show_header=True, box=box.SIMPLE_HEAVY)
            table.add_column("Finding",  width=36)
            table.add_column("Module",   width=18)
            table.add_column("Result",   width=12)
            table.add_column("Retries",  width=8)

            for r in results:
                status = "[green]PASSED[/green]" if r.passed else "[red]FAILED[/red]"
                table.add_row(r.finding_id[:8], r.module, status, str(r.retries))

            console.print(table)
            console.print(
                f"\n[bold]Summary:[/bold] "
                f"[green]{summary['passed']} passed[/green] / "
                f"[red]{summary['failed']} failed[/red] "
                f"([bold]{summary['pass_rate']}%[/bold] remediated)"
            )
        finally:
            db.close()

    asyncio.run(_run())


@app.command()
@click.argument("model")
@click.option("--chain",         default=None, help="Path to chain YAML template")
@click.option("--chain-type",    default=None, help="Built-in chain type: persona_anchoring, crescendo, context_poisoning, memory_exploitation, jailbreak_escalation, linear_jailbreak")
@click.option("--system-prompt", default=None, help="System prompt to test against")
@click.option("--objective",     default=None, help="Override chain objective")
def chain(model, chain, chain_type, system_prompt, objective):
    """Run a multi-turn attack chain against a model.

    \b
    Examples:
      lance chain ollama/llama3 --chain-type crescendo
      lance chain ollama/llama3 --chain lance/chains/templates/persona_anchoring.yaml
      lance chain openai/gpt-4o --chain-type linear_jailbreak --system-prompt "You are a helpful assistant."
    """
    print_banner()
    from pathlib import Path as _Path
    from lance.chains.engine import ChainEngine, load_chain, AttackChain, ChainTurn

    BUILTIN_CHAINS = {
        "persona_anchoring":   "lance/chains/templates/persona_anchoring.yaml",
        "crescendo":           "lance/chains/templates/crescendo.yaml",
        "context_poisoning":   "lance/chains/templates/context_poisoning.yaml",
        "memory_exploitation": "lance/chains/templates/memory_exploitation.yaml",
        "jailbreak_escalation":"lance/chains/templates/jailbreak_escalation.yaml",
        "linear_jailbreak":    "lance/chains/templates/linear_jailbreak.yaml",
    }

    chain_path = chain
    if chain_type:
        chain_path = BUILTIN_CHAINS.get(chain_type)
        if not chain_path:
            console.print(f"[red]Unknown chain type: {chain_type}[/red]")
            console.print(f"Available: {', '.join(BUILTIN_CHAINS.keys())}")
            raise SystemExit(1)

    if not chain_path:
        console.print("[red]Provide --chain or --chain-type[/red]")
        raise SystemExit(1)

    try:
        attack_chain = load_chain(chain_path)
    except FileNotFoundError:
        console.print(f"[red]Chain file not found: {chain_path}[/red]")
        raise SystemExit(1)

    if objective:
        attack_chain.objective = objective

    console.print(Panel(
        f"[bold]Chain:[/bold]     {attack_chain.name}\n"
        f"[bold]Type:[/bold]      {attack_chain.chain_type}\n"
        f"[bold]Objective:[/bold] {attack_chain.objective}\n"
        f"[bold]Turns:[/bold]     {len(attack_chain.turns)}",
        title="[bold blue]LANCE CHAIN[/bold blue]",
        border_style="blue",
    ))

    async def _run():
        engine = ChainEngine(model=model)
        result = await engine.run_chain(attack_chain, system_prompt=system_prompt)

        console.print(f"\n[bold]Result:[/bold] {'[red]COMPLIANCE DETECTED[/red]' if result.success else '[green]RESISTED[/green]'}")
        if result.compliance_turn:
            console.print(f"[bold]Compliance on turn:[/bold] {result.compliance_turn}/{result.turns_taken}")

        console.print("\n[bold]Conversation:[/bold]")
        for msg in result.conversation:
            role   = msg["role"]
            colour = "cyan" if role == "user" else "green" if role == "assistant" else "dim"
            console.print(f"  [{colour}]{role.upper()}:[/{colour}] {msg['content'][:200]}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
