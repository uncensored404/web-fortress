from urllib.parse import urljoin, urlparse
from typing import Set, List
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


class ControlledCrawler:
    def __init__(self, base_url: str, max_depth: int = 2, timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.found_urls: List[str] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WEB-FORTRESS/1.0 (Security Scanner by 404sec - Authorized use only)"
        })

    def is_same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_netloc
        except Exception:
            return False

    def crawl(self) -> List[str]:
        console.print(f"[cyan][*] Démarrage du crawl contrôlé (profondeur max = {self.max_depth})[/cyan]")
        self._crawl_recursive(self.base_url, depth=0)
        console.print(f"[green][+] Crawl terminé — {len(self.found_urls)} URL(s) découverte(s)[/green]")
        return self.found_urls

    def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return

        if not self.is_same_origin(url):
            return

        self.visited.add(url)
        self.found_urls.append(url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"])
                # Nettoyage basique
                link = link.split("#")[0].split("?")[0]
                if self.is_same_origin(link) and link not in self.visited:
                    self._crawl_recursive(link, depth + 1)

        except requests.RequestException:
            pass
