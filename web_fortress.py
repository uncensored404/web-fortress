#!/usr/bin/env python3
"""
WEB FORTRESS — Scanner avancé de sécurité web
Author: 404sec
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
import requests
from rich.console import Console

from core.crawler import ControlledCrawler
from core.headers_checker import check_security_headers
from core.sensitive_files import check_sensitive_files
from core.tls_checker import check_tls
from core.vuln_checks import check_basic_vulns
from core.report import print_report, export_json, export_html

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="WEB FORTRESS — Scanner de sécurité web (by 404sec)"
    )
    parser.add_argument("url", help="URL cible (ex: https://exemple.com)")
    parser.add_argument("--depth", type=int, default=1, help="Profondeur max du crawl (défaut: 1)")
    parser.add_argument("--no-crawl", action="store_true", help="Désactiver le crawl (scan uniquement l'URL fournie)")
    parser.add_argument("-o", "--output", default="web_fortress_report", help="Nom de base des rapports")
    parser.add_argument("--no-html", action="store_true", help="Ne pas générer le rapport HTML")
    parser.add_argument("--no-json", action="store_true", help="Ne pas générer le rapport JSON")

    args = parser.parse_args()
    target = args.url.rstrip("/")

    if not target.startswith(("http://", "https://")):
        console.print("[red][!] L'URL doit commencer par http:// ou https://[/red]")
        sys.exit(1)

    console.print(f"\n[bold cyan]🏰 WEB FORTRESS[/bold cyan] — by 404sec")
    console.print(f"[dim]Cible : {target}[/dim]\n")
    console.print("[yellow]Rappel : n'utilisez cet outil que sur des cibles autorisées.[/yellow]\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "WEB-FORTRESS/1.0 (Security Scanner by 404sec - Authorized use only)"
    })

    all_findings = []

    # 1. TLS
    console.print("[*] Vérification TLS...")
    all_findings.extend(check_tls(target))

    # 2. Headers de sécurité
    console.print("[*] Vérification des en-têtes de sécurité...")
    all_findings.extend(check_security_headers(target, session))

    # 3. Fichiers sensibles
    console.print("[*] Recherche de fichiers/dossiers sensibles...")
    all_findings.extend(check_sensitive_files(target, session))

    # 4. Vulnérabilités basiques
    console.print("[*] Contrôles de vulnérabilités basiques...")
    all_findings.extend(check_basic_vulns(target, session))

    # 5. Crawl contrôlé + headers sur les pages découvertes
    urls_to_check = [target]
    if not args.no_crawl:
        crawler = ControlledCrawler(target, max_depth=args.depth)
        discovered = crawler.crawl()
        urls_to_check = list(set(discovered))[:30]  # limite de sécurité

        console.print("[*] Vérification des headers sur les pages découvertes...")
        for u in urls_to_check[1:]:  # on a déjà fait la page d'accueil
            all_findings.extend(check_security_headers(u, session))

    # Rapport
    print_report(all_findings, target)

    output_base = Path(args.output)
    if not args.no_json:
        export_json(all_findings, target, output_base.with_suffix(".json"))
    if not args.no_html:
        export_html(all_findings, target, output_base.with_suffix(".html"))

    console.print("\n[green][+] Scan terminé.[/green]\n")


if __name__ == "__main__":
    main()
