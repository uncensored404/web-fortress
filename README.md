# 🏰 WEB FORTRESS

**Scanner avancé de sécurité web — by 404sec**

---

### Description

WEB FORTRESS est un scanner de sécurité web défensif destiné aux applications que **vous possédez** ou que **vous êtes autorisé à auditer**.

Il s’inspire des bonnes pratiques OWASP et de l’approche d’outils comme OWASP ZAP, tout en restant simple, transparent et orienté rapports clairs.

### Fonctionnalités

- Exploration contrôlée des pages (crawl limité + même origine)
- Vérification des en-têtes de sécurité HTTP (CSP, HSTS, X-Frame-Options, etc.)
- Détection de fichiers/dossiers sensibles exposés
- Contrôles de base de la configuration TLS
- Détection de certaines failles courantes en environnement de test
- Classement des résultats par gravité
- Génération de preuves techniques + recommandations
- Rapport console + export JSON / HTML

### ⚠️ Avertissement légal

**N’utilisez cet outil que sur des cibles pour lesquelles vous avez une autorisation explicite.**  
L’utilisation non autorisée d’un scanner de vulnérabilités est illégale dans la plupart des pays.

### Installation

```bash
git clone https://github.com/404sec/web-fortress.git
cd web-fortress
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
```

### Utilisation

```bash
python web_fortress.py https://exemple.com
```

Options utiles :
```bash
python web_fortress.py https://exemple.com --depth 2 --output mon_rapport
python web_fortress.py https://exemple.com --no-crawl
```

### Auteur

**404sec**

### Disclaimer

Outil purement défensif et éducatif.  
L’auteur décline toute responsabilité en cas d’usage non autorisé.
