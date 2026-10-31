from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests


def check_basic_vulns(url: str, session: requests.Session = None) -> List[Dict]:
    """Quelques contrôles basiques et non destructifs (environnement de test)."""
    findings = []
    sess = session or requests.Session()

    # 1. Open Redirect basique (paramètres courants)
    findings.extend(_check_open_redirect(url, sess))

    # 2. Directory listing
    findings.extend(_check_directory_listing(url, sess))

    # 3. Cookies sans flags de sécurité
    findings.extend(_check_cookies(url, sess))

    return findings


def _check_open_redirect(url: str, session: requests.Session) -> List[Dict]:
    findings = []
    payloads = ["https://example.com", "//example.com"]
    params_to_test = ["url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "dest"]

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for param in params_to_test:
        for payload in payloads:
            new_query = query.copy()
            new_query[param] = [payload]
            new_url = urlunparse(parsed._replace(query=urlencode(new_query, doseq=True)))

            try:
                resp = session.get(new_url, timeout=6, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "example.com" in location:
                    findings.append({
                        "title": f"Possible Open Redirect via paramètre '{param}'",
                        "severity": "medium",
                        "url": new_url,
                        "evidence": f"Redirection vers : {location}",
                        "recommendation": "Validez strictement les URLs de redirection (whitelist)",
                        "category": "Open Redirect"
                    })
                    break
            except requests.RequestException:
                continue
    return findings


def _check_directory_listing(url: str, session: requests.Session) -> List[Dict]:
    findings = []
    # Teste quelques dossiers courants
    candidates = ["/images/", "/uploads/", "/static/", "/assets/", "/files/", "/backup/"]
    base = url.rstrip("/")

    for path in candidates:
        test_url = base + path
        try:
            resp = session.get(test_url, timeout=6)
            if resp.status_code == 200 and ("Index of /" in resp.text or "Directory listing" in resp.text):
                findings.append({
                    "title": f"Directory Listing activé : {path}",
                    "severity": "medium",
                    "url": test_url,
                    "evidence": "Page de listing de répertoire détectée",
                    "recommendation": "Désactivez le directory listing sur le serveur web",
                    "category": "Misconfiguration"
                })
        except requests.RequestException:
            continue
    return findings


def _check_cookies(url: str, session: requests.Session) -> List[Dict]:
    findings = []
    try:
        resp = session.get(url, timeout=8)
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure manquant")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                # Approximation simple
                issues.append("HttpOnly probablement manquant")

            if issues:
                findings.append({
                    "title": f"Cookie mal configuré : {cookie.name}",
                    "severity": "medium",
                    "url": url,
                    "evidence": f"Problèmes : {', '.join(issues)}",
                    "recommendation": "Ajoutez les flags Secure et HttpOnly sur les cookies de session",
                    "category": "Cookie Security"
                })
    except requests.RequestException:
        pass
    return findings
