from typing import List, Dict
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime


def check_tls(url: str) -> List[Dict]:
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append({
            "title": "Le site n'utilise pas HTTPS",
            "severity": "high",
            "url": url,
            "evidence": f"Schéma détecté : {parsed.scheme}",
            "recommendation": "Forcez HTTPS et redirigez tout le trafic HTTP vers HTTPS",
            "category": "TLS"
        })
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

                # Version TLS
                if version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "title": f"Version TLS obsolète : {version}",
                        "severity": "high",
                        "url": url,
                        "evidence": f"Version négociée : {version}",
                        "recommendation": "Désactivez TLSv1 et TLSv1.1, gardez uniquement TLSv1.2+",
                        "category": "TLS"
                    })
                elif version == "TLSv1.2":
                    findings.append({
                        "title": "TLS 1.2 utilisé (acceptable mais perfectible)",
                        "severity": "info",
                        "url": url,
                        "evidence": f"Version : {version}",
                        "recommendation": "Envisagez d'activer TLSv1.3",
                        "category": "TLS"
                    })

                # Expiration du certificat
                not_after = cert.get("notAfter")
                if not_after:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "title": "Certificat SSL expiré",
                            "severity": "critical",
                            "url": url,
                            "evidence": f"Expiré depuis {-days_left} jours",
                            "recommendation": "Renouvelez immédiatement le certificat",
                            "category": "TLS"
                        })
                    elif days_left < 30:
                        findings.append({
                            "title": "Certificat SSL bientôt expiré",
                            "severity": "medium",
                            "url": url,
                            "evidence": f"Expire dans {days_left} jours ({not_after})",
                            "recommendation": "Planifiez le renouvellement du certificat",
                            "category": "TLS"
                        })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title": "Erreur de validation du certificat SSL",
            "severity": "high",
            "url": url,
            "evidence": str(e),
            "recommendation": "Vérifiez la chaîne de certificats et le nom d'hôte",
            "category": "TLS"
        })
    except Exception as e:
        findings.append({
            "title": "Impossible de vérifier TLS",
            "severity": "info",
            "url": url,
            "evidence": str(e),
            "recommendation": "Vérifiez la connectivité et le certificat manuellement",
            "category": "TLS"
        })

    return findings
