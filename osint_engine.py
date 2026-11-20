import asyncio
import aiohttp
import base64
import json
import os
import random
import re
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse
from dotenv import load_dotenv

load_dotenv()

# ---------- تنضيف والتحقق من الدومينات (منقول ومحسن) ----------
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ROOT_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def clean_root_domain(raw_input: str) -> Optional[str]:
    """ينظف المدخل ويتأكد إنه دومين حقيقي صالح مش نص عشوائي"""
    if not isinstance(raw_input, str):
        return None
    d = raw_input.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = re.sub(r"/.*$", "", d)
    d = re.sub(r":\d+$", "", d)
    d = d.rstrip(".")
    return d if ROOT_DOMAIN_RE.match(d) else None


def normalize_subdomains(raw_items: List[str], root: str) -> List[str]:
    """ينظف السابدومينات ويشيل التكرار والـ wildcards والرموز الغلط"""
    out: Set[str] = set()
    suffix = "." + root
    for chunk in raw_items:
        for part in re.split(r"[\s,]+", str(chunk)):
            h = part.strip().lower()
            if not h:
                continue
            h = re.sub(r"^\*\.", "", h)
            h = re.sub(r"^\*+", "", h).rstrip(".")
            h = re.sub(r":\d+$", "", h)
            if "@" in h:
                h = h.split("@")[-1]
            if h != root and not h.endswith(suffix):
                continue
            if len(h) > 253:
                continue
            if not all(LABEL_RE.match(lbl) for lbl in h.split(".")):
                continue
            if h != root:
                out.add(h)
    return sorted(out)


def labels_to_hosts(labels: List[str], root: str) -> List[str]:
    return [f"{lbl}.{root}" for lbl in labels if lbl]


async def check_domain_dns(domain: str) -> bool:
    """يتحقق هل الدومين له وجود فعلي في الـ DNS ولا لأ"""
    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


# ---------- إدارة البروكسيات ----------
class ProxyManager:
    def __init__(self):
        self.working_proxies: List[str] = []
        self.proxy_sources = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all",
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        ]

    async def fetch_raw_proxies(self, session: aiohttp.ClientSession) -> Set[str]:
        raw_proxies: Set[str] = set()
        for url in self.proxy_sources:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and ":" in line:
                                raw_proxies.add(f"http://{line}")
            except Exception:
                pass
        return raw_proxies

    async def validate_proxy(self, session: aiohttp.ClientSession, proxy: str, sem: asyncio.Semaphore):
        async with sem:
            try:
                async with session.get(
                    "http://httpbin.org/ip",
                    proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=4),
                ) as resp:
                    if resp.status == 200:
                        self.working_proxies.append(proxy)
            except Exception:
                pass

    async def initialize_proxies(self, max_to_test: int = 120):
        print("[*] Fetching and validating free proxies...")
        sem = asyncio.Semaphore(50)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            all_proxies = list(await self.fetch_raw_proxies(session))
            random.shuffle(all_proxies)
            tasks = [self.validate_proxy(session, p, sem) for p in all_proxies[:max_to_test]]
            await asyncio.gather(*tasks)
        print(f"[+] Proxy Pool Ready: {len(self.working_proxies)} working proxies.")

    def get_proxy(self) -> Optional[str]:
        return random.choice(self.working_proxies) if self.working_proxies else None

    def get_headers(self, extra_headers: Optional[dict] = None) -> dict:
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/plain, */*",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers


# ---------- إدارة المفاتيح (يدعم .env و config.json معاً) ----------
class KeyRing:
    ENV_MAP = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "securitytrails": "SECURITYTRAILS_API_KEY",
        "shodan": "SHODAN_API_KEY",
        "github": "GITHUB_TOKEN",
        "censys_id": "CENSYS_API_ID",
        "censys_secret": "CENSYS_API_SECRET",
    }

    def __init__(self, config_path: str = "config.json"):
        self.keys: Dict[str, List[str]] = {}
        # 1) تحميل من config.json لو موجود
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for service, k_list in data.items():
                        if isinstance(k_list, str):
                            k_list = [k_list]
                        valid = [k.strip() for k in k_list if k and not k.startswith("PUT_YOUR_")]
                        if valid:
                            self.keys[service.lower()] = valid
            except Exception as e:
                print(f"[!] Error reading {config_path}: {e}")

        # 2) تحميل من ملف .env (لو المفتاح موجود هناك يضيفه)
        for service, env_var in self.ENV_MAP.items():
            val = os.getenv(env_var, "").strip()
            if val and not val.startswith("PUT_YOUR_"):
                self.keys.setdefault(service, [])
                if val not in self.keys[service]:
                    self.keys[service].append(val)

    def get_key(self, service: str) -> Optional[str]:
        service_keys = self.keys.get(service.lower(), [])
        return random.choice(service_keys) if service_keys else None


# ---------- المحرك الموحد ----------
class AdvancedOSINTEngine:
    def __init__(self, target_domain: str, concurrency_limit: int = 10, use_proxies: bool = False):
        cleaned = clean_root_domain(target_domain)
        if not cleaned:
            raise ValueError(f"Invalid root domain: {target_domain}")
        self.target = cleaned
        self.use_proxies = use_proxies
        self.proxy_manager = ProxyManager()
        self.keyring = KeyRing()
        self.semaphore = asyncio.Semaphore(concurrency_limit)

        self.subdomain_sources: Dict[str, Set[str]] = {}
        self.sources_report: List[Dict] = []

        escaped = re.escape(self.target)
        self.subdomain_regex = re.compile(
            rf"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{escaped}",
            re.IGNORECASE,
        )

    async def _request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        json_body: Optional[dict] = None,
        retries: int = 2,
        timeout_sec: int = 20,
    ) -> Tuple[int, str]:
        last_err = ""
        for attempt in range(retries + 1):
            proxy = self.proxy_manager.get_proxy() if (self.use_proxies and attempt < retries) else None
            req_headers = self.proxy_manager.get_headers(headers)
            try:
                async with self.semaphore:
                    await asyncio.sleep(random.uniform(0.15, 0.5))
                    async with session.request(
                        method,
                        url,
                        headers=req_headers,
                        json=json_body,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout_sec),
                    ) as resp:
                        text = await resp.text()
                        if resp.status == 429 or resp.status >= 500:
                            if attempt == retries:
                                return resp.status, text
                            retry_after = resp.headers.get("Retry-After")
                            wait = float(retry_after) if (retry_after and retry_after.isdigit()) else (2 ** attempt)
                            await asyncio.sleep(min(wait, 8))
                            continue
                        return resp.status, text
            except Exception as e:
                last_err = str(e)
                if attempt == retries:
                    raise RuntimeError(last_err)
                await asyncio.sleep(1.0 * (2 ** attempt))
        raise RuntimeError(last_err or "Request failed")

    # --- المصادر المجانية ---
    async def _src_crtsh(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://crt.sh/?q={quote('%.' + self.target)}&output=json"
        status, text = await self._request(session, url, timeout_sec=30)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        rows = json.loads(text)
        return [r.get("name_value", "") for r in rows if isinstance(r, dict)]

    async def _src_wayback(self, session: aiohttp.ClientSession) -> List[str]:
        url = (
            f"https://web.archive.org/cdx/search/cdx?url={quote(self.target)}"
            "&matchType=domain&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        status, text = await self._request(session, url, retries=0, timeout_sec=20)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        rows = json.loads(text)
        hosts = []
        for row in rows[1:]:
            try:
                host = urlparse(row[0]).hostname
                if host:
                    hosts.append(host)
            except Exception:
                pass
        return hosts

    async def _src_hackertarget(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        status, text = await self._request(session, url)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return self.subdomain_regex.findall(text)

    async def _src_alienvault(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
        status, text = await self._request(session, url)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return self.subdomain_regex.findall(text)

    async def _src_anubis(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://jldc.me/anubis/subdomains/{self.target}"
        status, text = await self._request(session, url)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return json.loads(text) if text.startswith("[") else self.subdomain_regex.findall(text)

    async def _src_urlscan(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"
        status, text = await self._request(session, url)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return self.subdomain_regex.findall(text)

    async def _src_rapiddns(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://rapiddns.io/subdomain/{self.target}?full=1"
        status, text = await self._request(session, url, timeout_sec=25)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return self.subdomain_regex.findall(text)

    async def _src_subdomaincenter(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://api.subdomain.center/?domain={self.target}"
        status, text = await self._request(session, url, timeout_sec=20)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = json.loads(text)
        return data if isinstance(data, list) else []

    async def _src_certspotter(self, session: aiohttp.ClientSession) -> List[str]:
        url = (
            f"https://api.certspotter.com/v1/issuances?domain={quote(self.target)}"
            "&include_subdomains=true&expand=dns_names"
        )
        status, text = await self._request(session, url, timeout_sec=20)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        rows = json.loads(text)
        names: List[str] = []
        if isinstance(rows, list):
            for item in rows:
                names.extend(item.get("dns_names", []))
        return names

    async def _src_threatminer(self, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://api.threatminer.org/v2/domain.php?q={quote(self.target)}&rt=5"
        status, text = await self._request(session, url, timeout_sec=20)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = json.loads(text)
        return data.get("results", []) if isinstance(data, dict) else []

    # --- مصادر الـ API Keys (مدمجة من مشروع صاحبك) ---
    async def _src_virustotal(self, session: aiohttp.ClientSession, api_key: str) -> List[str]:
        out: List[str] = []
        url: Optional[str] = f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains?limit=40"
        for _ in range(5):
            if not url:
                break
            status, text = await self._request(session, url, headers={"x-apikey": api_key})
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            data = json.loads(text)
            out.extend(item.get("id", "") for item in data.get("data", []))
            url = data.get("links", {}).get("next")
        return out

    async def _src_securitytrails(self, session: aiohttp.ClientSession, api_key: str) -> List[str]:
        url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains?children_only=false&include_inactive=true"
        status, text = await self._request(session, url, headers={"APIKEY": api_key})
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = json.loads(text)
        return labels_to_hosts(data.get("subdomains", []), self.target)

    async def _src_shodan(self, session: aiohttp.ClientSession, api_key: str) -> List[str]:
        url = f"https://api.shodan.io/dns/domain/{self.target}?key={api_key}"
        status, text = await self._request(session, url)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = json.loads(text)
        return labels_to_hosts(data.get("subdomains", []), self.target)

    async def _src_github(self, session: aiohttp.ClientSession, token: str) -> List[str]:
        found: List[str] = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.text-match+json",
            "User-Agent": "HiddenOSINT-Engine",
        }
        for page in range(1, 4):
            url = f"https://api.github.com/search/code?q={quote(f'\"{self.target}\"')}&per_page=100&page={page}"
            status, text = await self._request(session, url, headers=headers)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            body = json.loads(text)
            items = body.get("items", [])
            for item in items:
                for m in item.get("text_matches", []):
                    found.extend(self.subdomain_regex.findall(m.get("fragment", "")))
            if len(items) < 100:
                break
        return found

    async def _src_censys(self, session: aiohttp.ClientSession, api_id: str, api_secret: str) -> List[str]:
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
        out: List[str] = []
        cursor: Optional[str] = None
        for _ in range(3):
            payload = {"q": f"names: {self.target}", "per_page": 100}
            if cursor:
                payload["cursor"] = cursor
            status, text = await self._request(
                session,
                "https://search.censys.io/api/v2/certificates/search",
                method="POST",
                headers=headers,
                json_body=payload,
            )
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            body = json.loads(text)
            for hit in body.get("result", {}).get("hits", []):
                out.extend(hit.get("names", []))
            cursor = body.get("result", {}).get("links", {}).get("next")
            if not cursor:
                break
        return out

    async def _run_source(self, name: str, coro):
        try:
            raw = await coro
            hosts = normalize_subdomains(raw, self.target)
            for h in hosts:
                self.subdomain_sources.setdefault(h, set()).add(name)
            self.sources_report.append({"source": name, "status": "done", "found": len(hosts), "error": None})
            print(f"[+] {name}: {len(hosts)} subdomains")
        except Exception as e:
            err_msg = str(e)[:180]
            self.sources_report.append({"source": name, "status": "failed", "found": 0, "error": err_msg})
            print(f"[-] {name} failed: {err_msg}")

    async def run_detailed(self) -> Dict:
        """تشغيل الفحص وإرجاع النتيجة الكاملة (الدومينات + حالة كل مصدر + فحص الـ DNS)"""
        if self.use_proxies:
            await self.proxy_manager.initialize_proxies()

        dns_exists = await check_domain_dns(self.target)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._run_source("crt.sh", self._src_crtsh(session)),
                self._run_source("WaybackMachine", self._src_wayback(session)),
                self._run_source("HackerTarget", self._src_hackertarget(session)),
                self._run_source("AlienVault OTX", self._src_alienvault(session)),
                self._run_source("AnubisDB", self._src_anubis(session)),
                self._run_source("URLScan.io", self._src_urlscan(session)),
               
                self._run_source("RapidDNS", self._src_rapiddns(session)),
                self._run_source("SubdomainCenter", self._src_subdomaincenter(session)),
                self._run_source("CertSpotter", self._src_certspotter(session)),
                self._run_source("ThreatMiner", self._src_threatminer(session)),
            ]

            # إضافة المصادر المدفوعة/المجانية اللي بتحتاج API Key لو المفاتيح موجودة
            vt_key = self.keyring.get_key("virustotal")
            if vt_key:
                tasks.append(self._run_source("VirusTotal", self._src_virustotal(session, vt_key)))
            else:
                self.sources_report.append({"source": "VirusTotal", "status": "skipped", "found": 0, "error": "missing API key"})

            st_key = self.keyring.get_key("securitytrails")
            if st_key:
                tasks.append(self._run_source("SecurityTrails", self._src_securitytrails(session, st_key)))
            else:
                self.sources_report.append({"source": "SecurityTrails", "status": "skipped", "found": 0, "error": "missing API key"})

            shodan_key = self.keyring.get_key("shodan")
            if shodan_key:
                tasks.append(self._run_source("Shodan", self._src_shodan(session, shodan_key)))
            else:
                self.sources_report.append({"source": "Shodan", "status": "skipped", "found": 0, "error": "missing API key"})

            gh_token = self.keyring.get_key("github")
            if gh_token:
                tasks.append(self._run_source("GitHub", self._src_github(session, gh_token)))
            else:
                self.sources_report.append({"source": "GitHub", "status": "skipped", "found": 0, "error": "missing API key"})

            c_id = self.keyring.get_key("censys_id")
            c_sec = self.keyring.get_key("censys_secret")
            if c_id and c_sec:
                tasks.append(self._run_source("Censys", self._src_censys(session, c_id, c_sec)))
            else:
                self.sources_report.append({"source": "Censys", "status": "skipped", "found": 0, "error": "missing API key"})

            await asyncio.gather(*tasks)

        sorted_subs = sorted(self.subdomain_sources.keys())
        detailed_subs = [
            {"subdomain": sub, "sources": sorted(list(self.subdomain_sources[sub]))}
            for sub in sorted_subs
        ]

        return {
            "target": self.target,
            "dns_exists": dns_exists,
            "total_found": len(sorted_subs),
            "subdomains": sorted_subs,
            "detailed_subdomains": detailed_subs,
            "sources": self.sources_report,
        }

    async def run(self) -> List[str]:
        """للتوافق مع osint_data_layer القديم لو لسه شغال"""
        res = await self.run_detailed()
        return res["subdomains"]


if __name__ == "__main__":
    engine = AdvancedOSINTEngine(target_domain="example.com", use_proxies=False)
    report = asyncio.run(engine.run_detailed())
    print(json.dumps(report, indent=2, ensure_ascii=False))