from typing import List, Dict
from urllib.parse import urljoin
import requests


# Liste de chemins sensibles courants (non exhaustive)
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/wp-config.php",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/admin",
    "/administrator",
    "/login",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/api/swagger",
    "/swagger-ui.html",
    "/graphql",
    "/.DS_Store",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/robots.txt",
    "/sitemap.xml",
]


def check_sensitive_files(base_url: str, session: requests.Session = None) -> List[Dict]:
    findings = []
    sess = session or requests.Session()
    base_url = base_url.rstrip("/")

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            resp = sess.get(url, timeout=6, allow_redirects=False)

            # On considère intéressant les 200 et certains 403
            if resp.status_code == 200:
                severity = "high"
                if path in ["/robots.txt", "/sitemap.xml"]:
                    severity = "info"

                findings.append({
                    "title": f"Fichier/dossier sensible accessible : {path}",
                    "severity": severity,
                    "url": url,
                    "evidence": f"Status {resp.status_code} — Taille réponse : {len(resp.content)} octets",
                    "recommendation": f"Restreignez l'accès à {path} ou supprimez-le s'il n'est pas nécessaire",
                    "category": "Sensitive Files"
                })

            elif resp.status_code == 403 and path.startswith("/.git"):
                findings.append({
                    "title": f"Présence probable de .git (403)",
                    "severity": "medium",
                    "url": url,
                    "evidence": f"Status 403 sur {path}",
                    "recommendation": "Assurez-vous que le dossier .git n'est pas accessible depuis le web",
                    "category": "Sensitive Files"
                })

        except requests.RequestException:
            continue

    return findings
