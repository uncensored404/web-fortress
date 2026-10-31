from typing import List, Dict
from datetime import datetime
from pathlib import Path
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim"
}


def print_report(findings: List[Dict], target: str):
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]WEB FORTRESS[/bold cyan] — Rapport de sécurité\n[dim]by 404sec[/dim]",
        border_style="cyan"
    ))
    console.print(f"\n[bold]Cible :[/bold] {target}")
    console.print(f"[bold]Date  :[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"[bold]Total findings :[/bold] {len(findings)}\n")

    # Stats par gravité
    stats = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        stats[f.get("severity", "info")] += 1

    table = Table(box=box.SIMPLE)
    table.add_column("Gravité", style="bold")
    table.add_column("Nombre")
    for sev in ["critical", "high", "medium", "low", "info"]:
        table.add_row(sev.upper(), str(stats[sev]), style=SEVERITY_COLOR.get(sev))
    console.print(table)

    # Détail
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 99))

    for f in sorted_findings:
        sev = f.get("severity", "info")
        color = SEVERITY_COLOR.get(sev, "white")
        console.print(f"\n[{color}][{sev.upper()}] {f['title']}[/{color}]")
        console.print(f"  Catégorie      : {f.get('category', 'N/A')}")
        console.print(f"  URL            : {f.get('url', 'N/A')}")
        console.print(f"  Preuve         : {f.get('evidence', 'N/A')}")
        console.print(f"  Recommandation : {f.get('recommendation', 'N/A')}")


def export_json(findings: List[Dict], target: str, output_path: Path):
    data = {
        "tool": "WEB FORTRESS",
        "author": "404sec",
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    console.print(f"\n[green]✓ Rapport JSON : {output_path}[/green]")


def export_html(findings: List[Dict], target: str, output_path: Path):
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 99))

    rows = ""
    for f in sorted_findings:
        sev = f.get("severity", "info")
        rows += f"""
        <tr>
            <td><span class="badge {sev}">{sev.upper()}</span></td>
            <td>{f.get('title', '')}</td>
            <td>{f.get('category', '')}</td>
            <td class="url">{f.get('url', '')}</td>
            <td>{f.get('evidence', '')}</td>
            <td>{f.get('recommendation', '')}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>WEB FORTRESS Report - {target}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f1419; color: #e7e9ea; padding: 30px; }}
        h1 {{ color: #1d9bf0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2f3336; vertical-align: top; }}
        th {{ background: #15202b; color: #8b98a5; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .critical {{ background: rgba(244,33,46,0.15); color: #f4212e; }}
        .high {{ background: rgba(255,122,0,0.15); color: #ff7a00; }}
        .medium {{ background: rgba(255,212,0,0.15); color: #ffd400; }}
        .low {{ background: rgba(0,186,124,0.15); color: #00ba7c; }}
        .info {{ background: rgba(139,152,165,0.15); color: #8b98a5; }}
        .url {{ max-width: 260px; word-break: break-all; font-size: 13px; color: #8b98a5; }}
    </style>
</head>
<body>
    <h1>🏰 WEB FORTRESS</h1>
    <p>Rapport de sécurité web — by 404sec</p>
    <p><strong>Cible :</strong> {target}<br>
    <strong>Date :</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    <strong>Findings :</strong> {len(findings)}</p>

    <table>
        <thead>
            <tr>
                <th>Gravité</th>
                <th>Titre</th>
                <th>Catégorie</th>
                <th>URL</th>
                <th>Preuve</th>
                <th>Recommandation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <p style="margin-top:40px;color:#8b98a5;font-size:13px;">
        WEB FORTRESS — Outil défensif. Utilisation uniquement sur des cibles autorisées.
    </p>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[green]✓ Rapport HTML : {output_path}[/green]")
