from __future__ import annotations

import os
import sys
from pathlib import Path

# Load .env from repo root if present
def _load_env():
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

_load_env()

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from paperscan.scanner import scan
from paperscan.models import ScanReport

console = Console()

_SEVERITY_COLOURS = {
    "clean": "green",
    "suspicious": "yellow",
    "malicious": "red",
}
_FINDING_COLOURS = {
    "low": "dim",
    "medium": "yellow",
    "high": "orange3",
    "critical": "red bold",
}
_SOPHISTICATION_COLOURS = {
    "basic": "green",
    "moderate": "yellow",
    "sophisticated": "orange3",
    "advanced": "red bold",
}


def _score_bar(score: int, width: int = 30) -> Text:
    filled = int(score / 100 * width)
    colour = "green" if score <= 20 else "yellow" if score <= 60 else "red"
    bar = "#" * filled + "-" * (width - filled)
    text = Text()
    text.append(f"[{bar}] ", style=colour)
    text.append(f"{score}/100", style=f"{colour} bold")
    return text


def _print_report(report: ScanReport, verbose: bool) -> None:
    sev_colour = _SEVERITY_COLOURS.get(report.severity, "white")

    # ── Header ────────────────────────────────────────────────────────────────
    header = Text()
    header.append(f"  {Path(report.file).name}\n", style="bold")
    header.append("  Severity: ")
    header.append(report.severity.upper(), style=f"{sev_colour} bold")
    header.append("   Score: ")
    header.append(_score_bar(report.score))
    if report.document_type and report.document_type != "unknown":
        header.append(f"\n  Document type: ")
        header.append(report.document_type.replace("_", " ").title(), style="cyan")
    if report.attack_sophistication:
        soph_colour = _SOPHISTICATION_COLOURS.get(report.attack_sophistication, "white")
        header.append("   Sophistication: ")
        header.append(report.attack_sophistication.upper(), style=soph_colour)
    ms = report.scan_duration_ms
    if ms >= 60_000:
        duration_str = f"{ms // 60_000}m {(ms % 60_000) // 1000}s"
    elif ms >= 1_000:
        duration_str = f"{ms / 1000:.1f}s"
    else:
        duration_str = f"{ms}ms"
    header.append(f"\n  Hash: {report.file_hash[:16]}…  |  {duration_str}")

    console.print(Panel(header, title="[bold]Paperscan Report[/bold]", border_style=sev_colour))

    if not report.findings:
        console.print("[green]No findings — document appears clean.[/green]\n")
        return

    # ── Findings table ────────────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Layer",    style="dim", width=9)
    table.add_column("Sev",      width=8)
    table.add_column("Category", width=28)
    table.add_column("Vector",   width=22)
    table.add_column("Location", width=22)
    table.add_column("Evidence")

    for f in sorted(report.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.severity]):
        sev_style = _FINDING_COLOURS.get(f.severity, "white")
        evidence = f.evidence[:70] + ("…" if len(f.evidence) > 70 else "")
        table.add_row(
            f.layer,
            Text(f.severity, style=sev_style),
            f.category,
            f.attack_vector or "—",
            f.location,
            evidence,
        )

    console.print(table)

    # ── AI Risk Analysis (shown whenever risk_narrative is present) ───────────
    if report.risk_narrative or report.attack_scenario:
        console.print()
        console.print("[bold cyan]AI Risk Analysis[/bold cyan]")

        if report.risk_narrative:
            console.print(Panel(
                report.risk_narrative,
                title="Risk Narrative",
                border_style="cyan",
            ))

        if report.attack_scenario:
            console.print(Panel(
                report.attack_scenario,
                title="Attack Scenario",
                border_style="orange3",
            ))

        if report.remediation:
            remediation_text = "\n".join(f"  [{i+1}] {r}" for i, r in enumerate(report.remediation))
            console.print(Panel(
                remediation_text,
                title="Recommended Actions",
                border_style="green",
            ))

    # ── Verbose: semantic reasoning + extracted panels ────────────────────────
    if verbose:
        # LLM reasoning for semantic findings
        semantic_with_reasoning = [f for f in report.findings if f.layer == "semantic" and f.reasoning]
        if semantic_with_reasoning:
            console.print("\n[bold]LLM Reasoning (semantic findings)[/bold]")
            for f in semantic_with_reasoning[:5]:
                console.print(Panel(
                    f.reasoning,
                    title=f"[{f.severity}] {f.category} @ {f.location}",
                    border_style=_FINDING_COLOURS.get(f.severity, "white"),
                ))

        console.print("\n[bold]Extracted document panels:[/bold]")
        console.print(Panel(report.extracted.visible_text[:2000] or "(empty)", title="Visible Text"))
        if report.extracted.hidden_text:
            hidden_summary = "\n".join(
                f"[{h['method']}@{h['location']}]: {h['content'][:100]}"
                for h in report.extracted.hidden_text[:20]
            )
            console.print(Panel(hidden_summary, title="Hidden Text"))
        if report.extracted.metadata:
            meta = "\n".join(f"{k}: {v}" for k, v in report.extracted.metadata.items() if isinstance(v, str))
            console.print(Panel(meta[:2000], title="Metadata"))
        if report.extracted.actual_text_spans:
            spans = "\n".join(
                f"page{s['page']}: visual='{s.get('visual','')}' -> extracted='{s.get('extracted','')}'"
                for s in report.extracted.actual_text_spans[:10]
            )
            console.print(Panel(spans, title="/ActualText Substitutions"))
        if report.extracted.tracked_changes:
            changes = "\n".join(
                f"[{c['type']}:{c['author']}] {c['content'][:100]}"
                for c in report.extracted.tracked_changes[:10]
            )
            console.print(Panel(changes, title="Tracked Changes"))
        if report.extracted.ocg_hidden_text:
            ocg = "\n".join(
                f"[{h['layer_name']}]: {h['content'][:120]}"
                for h in report.extracted.ocg_hidden_text[:10]
            )
            console.print(Panel(ocg, title="OCG Hidden Layers"))
        if report.extracted.unicode_anomalies:
            ua = "\n".join(
                f"{a['category']} {a['codepoint']} x{a['count']}"
                for a in report.extracted.unicode_anomalies[:10]
            )
            console.print(Panel(ua, title="Unicode Anomalies"))


@click.group()
def main():
    """Paperscan — multi-layer prompt injection detector for documents."""


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON report")
@click.option("--verbose", "-v", is_flag=True, help="Show extracted panels and LLM reasoning")
@click.option("--deep", is_flag=True, help="Enable deep analysis (claude-sonnet-4-6 + extended thinking)")
def scan_cmd(file: str, as_json: bool, verbose: bool, deep: bool):
    """Scan FILE for prompt injection attempts.

    Supported formats: PDF, DOCX, HTML, EML, XLSX, CSV, JSON, XML
    """
    import os
    if deep:
        os.environ["PAPERSCAN_DEEP_ANALYSIS"] = "1"

    try:
        report = scan(file)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report, verbose)

    if report.severity == "malicious":
        sys.exit(2)
    elif report.severity == "suspicious":
        sys.exit(1)


main.add_command(scan_cmd, name="scan")

if __name__ == "__main__":
    main()
