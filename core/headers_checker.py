from typing import Dict, List
import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "recommendation": "Activez HSTS avec une durée suffisante (ex: max-age=31536000; includeSubDomains)"
    },
    "Content-Security-Policy": {
        "severity": "high",
        "recommendation": "Mettez en place une CSP stricte pour limiter XSS et injections de contenu"
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": "Ajoutez X-Frame-Options: DENY ou SAMEORIGIN pour se protéger du clickjacking"
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "recommendation": "Ajoutez X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": "Définissez une Referrer-Policy (ex: strict-origin-when-cross-origin)"
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Utilisez Permissions-Policy pour restreindre les APIs navigateur"
    },
    "X-XSS-Protection": {
        "severity": "info",
        "recommendation": "Header obsolète, mais sa présence n’est pas négative"
    }
}


def check_security_headers(url: str, session: requests.Session = None) -> List[Dict]:
    findings = []
    sess = session or requests.Session()

    try:
        resp = sess.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "title": f"Header de sécurité manquant : {header}",
                    "severity": info["severity"],
                    "url": url,
                    "evidence": f"Le header '{header}' est absent de la réponse",
                    "recommendation": info["recommendation"],
                    "category": "Security Headers"
                })
            else:
                # Contrôles basiques de valeur
                value = headers[header.lower()]
                if header == "Strict-Transport-Security" and "max-age=0" in value:
                    findings.append({
                        "title": "HSTS désactivé (max-age=0)",
                        "severity": "high",
                        "url": url,
                        "evidence": f"Valeur actuelle : {value}",
                        "recommendation": "Utilisez un max-age élevé (au moins 6 mois)",
                        "category": "Security Headers"
                    })

        # Server header disclosure
        if "server" in headers:
            findings.append({
                "title": "Information de serveur exposée",
                "severity": "low",
                "url": url,
                "evidence": f"Server: {headers['server']}",
                "recommendation": "Masquez ou minimisez le header Server",
                "category": "Information Disclosure"
            })

        if "x-powered-by" in headers:
            findings.append({
                "title": "Header X-Powered-By exposé",
                "severity": "low",
                "url": url,
                "evidence": f"X-Powered-By: {headers['x-powered-by']}",
                "recommendation": "Supprimez le header X-Powered-By",
                "category": "Information Disclosure"
            })

    except requests.RequestException as e:
        findings.append({
            "title": "Impossible de récupérer les headers",
            "severity": "info",
            "url": url,
            "evidence": str(e),
            "recommendation": "Vérifiez la disponibilité de la cible",
            "category": "Connectivity"
        })

    return findings
