#!/usr/bin/env python3
"""cfprobe — měřidlo studie „český web před/po změně Cloudflare" (TORUMATA P2).

Definice: rfc/2026-09-13-cloudflare-pred-po.md. Zdroj pravdy: SQLite (zapečetěné runy), git drží exporty.

  run      python3 scripts/cfprobe.py run --run-id cf-T0a-2026-09-14 --kind T0a \
               --population population/tranco-cz-2026-09-13.txt --db /mnt/backup/cfstudy/cfstudy.sqlite
  export   python3 scripts/cfprobe.py export --run-id cf-T0a-2026-09-14 --db ... --out runs/cf-T0a-2026-09-14
  selftest python3 scripts/cfprobe.py selftest --db /tmp/cfselftest.sqlite   (kontroly klasifikátoru + žebříku)

Guardy jsou fatální: existující run-id = exit 2; zapečetěný run odmítá zápis (triggery); export bez pečetě neexistuje.
"""
import argparse, asyncio, hashlib, ipaddress, json, os, random, re, sqlite3, subprocess, sys, time
from datetime import datetime, timezone

import httpx, zstandard
import dns.resolver

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CF_IPS_FILE = os.path.join(ROOT, "population", "cloudflare-ips-2026-09-13.txt")
CHROME_BIN = os.environ.get("CHROME_BIN", "/usr/bin/google-chrome")
# V kontejneru běží Chrome bez sandboxu (nemá user namespaces) a bez /dev/shm; obojí je součást identity měřidla → sidecar.
CONTAINER_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get("CFPROBE_CONTAINER") == "1" else []

# --- příčky žebříku (RFC §2b) -------------------------------------------------------------------------
CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/[IP odstraněna] Safari/537.36"
UA = {
    "L2":  CHROME_UA,                                                       # HTTP knihovna s UA prohlížeče (agent v masce)
    "L3":  "torumata-probe/0.1 (+https://torumata.com/probe)",              # poctivý vlastní UA
    "L3r": "python-requests/2.32.3",                                        # poctivý knihovní UA
    "L4a": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "L4b": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "L4c": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    "L4g": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "L5": "torumata-ai-train/0.1 (+https://torumata.com/probe)",   # v6.2: vlastní jméno bez napodobování, zní jako tréninkový crawler (RFC dodatek 18. 9., test E); vždy poslední
    "L6": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",   # v6.3 (T3): vyhledavaci identita AI firmy; jen prurezove mezi rameny, nikdy do DiD proti T0a/T1 (RFC dodatek 23. 9.)
}
HTTP_RUNGS = list(UA.keys())
HTTP_RUNGS_BASE = [k for k in HTTP_RUNGS if k not in ("L5", "L6")]   # sada T0/T1; poradi se seedem se nemeni, L5 a L6 se pridavaji az za ni
HOLDOUT = set()            # v6.3: domeny bez napodobenych i vlastnich AI jmen (Opus A7): jen L0-L3r
HOLDOUT_EXCLUDE = ("L4a", "L4b", "L4c", "L4g", "L5", "L6")
EXTRA_PATHS = ["/llms.txt", "/llms-full.txt", "/ai.txt", "/sitemap.xml", "/.well-known/security.txt"]  # sběr pro statistiku (RFC §2 V6)
EXTRA_CAP = 1_000_000
PAGE_DEADLINE = 35        # s na jednu Chrome stránku (goto 20 + čekání 3 + content), tvrdý limit
DOMAIN_DEADLINE = 300     # s na celou doménu (všechny příčky); po překročení se doména zapíše s error=DomainDeadline
BROWSER_HDRS = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "cs,en;q=0.5", "Upgrade-Insecure-Requests": "1"}
AI_BOTS = ["GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User", "anthropic-ai", "Google-Extended",
           "PerplexityBot", "Perplexity-User", "CCBot", "Bytespider", "Amazonbot", "Applebot-Extended",
           "meta-externalagent", "Meta-ExternalFetcher", "cohere-ai", "Diffbot", "DuckAssistBot", "YouBot", "MistralAI-User"]
TRAIN_BOTS = ["GPTBot", "ClaudeBot", "anthropic-ai", "CCBot", "Google-Extended", "Bytespider", "Applebot-Extended",
              "meta-externalagent", "Amazonbot"]
AD_SIGS = {"adsbygoogle": r"adsbygoogle|pagead2\.googlesyndication", "doubleclick": r"doubleclick\.net",
           "sklik": r"sklik|ssp\.seznam\.cz|ssp\.imedia\.cz", "adform": r"adform\.net",
           "gam": r"googletagservices|securepubads", "prebid": r"prebid"}
CHALLENGE_RE = re.compile(r"Just a moment|Attention Required|cf-chl|challenge-platform|_cf_chl_opt|Verifying you are human", re.I)   # Cloudflare (pre-registrace T0)
# v6 (audit Opus N11): uzavřený seznam signatur blokových/challenge stránek dalších WAF — commitnuto před T1. Používá se pro `pass2`
# (zpřísněné čtení) vedle původního `pass`; obě se hlásí.
BLOCK_SIGS = {
    "cloudflare": CHALLENGE_RE,
    "akamai": re.compile(r"Access Denied.{0,200}Reference&#32;#|errors\.edgesuite\.net|akamai.{0,40}(denied|blocked)", re.I | re.S),
    "imperva": re.compile(r"Incapsula incident ID|_Incapsula_Resource|Request unsuccessful\. Incapsula|imperva", re.I),
    "datadome": re.compile(r"captcha-delivery\.com|datadome", re.I),
    "perimeterx": re.compile(r"px-captcha|perimeterx|_pxhc|Press & Hold", re.I),
    "distil": re.compile(r"Pardon Our Interruption|distil_r_captcha|Please verify you are a human", re.I),
    "captcha_interstitial": re.compile(r"<title>[^<]*captcha[^<]*</title>|hcaptcha\.com/1/api|Checking your browser", re.I),
    "generic_block": re.compile(r"<title>[^<]*(Access Denied|Forbidden|Request blocked|Bot detected|Blocked|Zakázaný přístup|Přístup odepřen)[^<]*</title>", re.I),
}
def block_signature(title, html):
    """Vrátí jméno první shodné signatury (kontrola titulku + prvních 8 kB), nebo None."""
    head = (title or "") + "\n" + (html or "")[:8000]
    for name, rx in BLOCK_SIGS.items():
        if rx.search(head): return name
    return None
PASS2_MIN_TEXT = 100   # obsahové kritérium pass2: text těla ≥ 100 znaků (Opus N11, redakční práh v kódu, commit před T1)

_SLD = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk", "nhs.uk", "com.pl", "net.pl", "org.pl", "edu.pl",
        "co.at", "or.at", "ac.at", "gv.at", "com.es", "org.es", "nom.es", "gob.es", "edu.es", "com.fr", "asso.fr", "gouv.fr", "co.it", "gov.it", "edu.it"}
def reg_domain(host):
    """Registrovaná doména (heuristika: 2 labely, nebo 3 u známých SLD jako co.uk). Pro příznak 'přesměrování na cizí doménu' (Opus N3)."""
    if not host: return None
    h = host.lower().rstrip(".").split(":")[0]; parts = h.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SLD: return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h
ADS_LINE_RE = re.compile(r"^\s*[A-Za-z0-9.\-]+\.[a-z]{2,}\s*,\s*[^,\s]+\s*,\s*(DIRECT|RESELLER)\b", re.I | re.M)

# --- schéma ------------------------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, kind TEXT, started TEXT, finished TEXT, sealed_at TEXT,
  script_commit TEXT, script_sha TEXT, population_file TEXT, population_sha TEXT, cf_ips_sha TEXT, egress_ip TEXT,
  egress_org TEXT, resolvers TEXT, chrome_version TEXT, httpx_version TEXT, python_version TEXT, seed INTEGER,
  ua_json TEXT, n_domains INTEGER, n_errors INTEGER, notes TEXT);
CREATE TABLE IF NOT EXISTS population(pop_id TEXT, domain TEXT, rank INTEGER, source TEXT, cc TEXT, stratum TEXT, PRIMARY KEY(pop_id, domain));
CREATE TABLE IF NOT EXISTS dns(run_id TEXT, domain TEXT, resolver TEXT, ns_json TEXT, a_json TEXT, aaaa_json TEXT,
  ns_cf INTEGER, ip_cf INTEGER, error TEXT, PRIMARY KEY(run_id, domain, resolver));
CREATE TABLE IF NOT EXISTS fetch(run_id TEXT, domain TEXT, rung TEXT, url TEXT, url_final TEXT, host_final TEXT,
  status INTEGER, cf_mitigated TEXT, cf_ray TEXT, server TEXT, content_type TEXT, title TEXT, text_len INTEGER,
  challenge INTEGER, pass INTEGER, elapsed_ms INTEGER, error TEXT, headers_sha TEXT, body_sha TEXT, ts TEXT,
  PRIMARY KEY(run_id, domain, rung));
CREATE TABLE IF NOT EXISTS blobs(sha256 TEXT PRIMARY KEY, bytes_zstd BLOB, size_raw INTEGER, mime TEXT, first_seen_run TEXT);
CREATE TABLE IF NOT EXISTS robots(run_id TEXT, domain TEXT, via TEXT, status INTEGER, body_sha TEXT, is_text INTEGER,
  cf_managed INTEGER, content_signal TEXT, stances_json TEXT, star_blocked INTEGER, ai_blocked_n INTEGER,
  train_blocked INTEGER, PRIMARY KEY(run_id, domain));
CREATE TABLE IF NOT EXISTS ads(run_id TEXT, domain TEXT, via TEXT, status INTEGER, body_sha TEXT, valid_lines INTEGER,
  html_sigs_json TEXT, html_ads INTEGER, PRIMARY KEY(run_id, domain));
CREATE TABLE IF NOT EXISTS domain_summary(run_id TEXT, domain TEXT, cc TEXT, stratum TEXT, cf_class TEXT, ns_cf INTEGER, ip_cf INTEGER,
  hdr_cf INTEGER, resolver_mismatch INTEGER, unreachable INTEGER, llms_txt INTEGER, jsonld INTEGER, js_dep_ratio REAL,
  PRIMARY KEY(run_id, domain));
CREATE TABLE IF NOT EXISTS extra(run_id TEXT, domain TEXT, path TEXT, via TEXT, status INTEGER, content_type TEXT,
  size INTEGER, is_text INTEGER, body_sha TEXT, PRIMARY KEY(run_id, domain, path));
CREATE TABLE IF NOT EXISTS derived(run_id TEXT, domain TEXT, extractor TEXT, extractor_commit TEXT, key TEXT, value TEXT,
  PRIMARY KEY(run_id, domain, extractor, key));
CREATE TABLE IF NOT EXISTS summary(run_id TEXT, cf_class TEXT, metric TEXT, value REAL, n INTEGER, computed_by_commit TEXT,
  PRIMARY KEY(run_id, cf_class, metric));
"""
SEAL_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS seal_{t}_upd BEFORE UPDATE ON {t} FOR EACH ROW
  WHEN (SELECT sealed_at FROM runs WHERE run_id=OLD.run_id) IS NOT NULL BEGIN SELECT RAISE(ABORT,'run sealed'); END;
CREATE TRIGGER IF NOT EXISTS seal_{t}_del BEFORE DELETE ON {t} FOR EACH ROW
  WHEN (SELECT sealed_at FROM runs WHERE run_id=OLD.run_id) IS NOT NULL BEGIN SELECT RAISE(ABORT,'run sealed'); END;
CREATE TRIGGER IF NOT EXISTS seal_{t}_ins BEFORE INSERT ON {t} FOR EACH ROW
  WHEN (SELECT sealed_at FROM runs WHERE run_id=NEW.run_id) IS NOT NULL BEGIN SELECT RAISE(ABORT,'run sealed'); END;
"""

MIGRATIONS = [  # v6: nové sloupce (ALTER TABLE ADD COLUMN je bezpečné vůči pečeti — nemění řádky)
    ("fetch", "cf_ray_first TEXT"), ("fetch", "status_first INTEGER"), ("fetch", "foreign_redirect INTEGER"), ("fetch", "block_sig TEXT"),
    ("dns", "cname_json TEXT"),
    ("robots", "unobservable INTEGER"), ("ads", "unobservable INTEGER"), ("extra", "unobservable INTEGER"),
    ("domain_summary", "reachable INTEGER"), ("domain_summary", "cname_foreign INTEGER"),
]
def open_db(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    db = sqlite3.connect(path, timeout=60)
    db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)
    for t, col in MIGRATIONS:
        if col.split()[0] not in [c[1] for c in db.execute(f"PRAGMA table_info({t})")]:
            db.execute(f"ALTER TABLE {t} ADD COLUMN {col}")
    for t in ("dns", "fetch", "robots", "ads", "extra", "domain_summary", "derived"):
        db.executescript(SEAL_TRIGGERS.format(t=t))
    return db

def sha256(b): return hashlib.sha256(b).hexdigest()
def now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def git_commit():
    try:
        out = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if out: return out
    except Exception: pass
    return os.environ.get("CFPROBE_SCRIPT_COMMIT")   # v kontejneru není git; commit předá build (--build-arg)
def git_dirty():
    if os.environ.get("CFPROBE_SCRIPT_COMMIT"): return False   # obraz je neměnný, commit nese tag obrazu
    try: return bool(subprocess.run(["git", "-C", ROOT, "status", "--porcelain", "scripts/cfprobe.py"], capture_output=True, text=True).stdout.strip())
    except Exception: return True

def load_cf_ranges():
    nets = [ipaddress.ip_network(l.strip()) for l in open(CF_IPS_FILE) if l.strip() and not l.startswith("#")]
    return nets, sha256(open(CF_IPS_FILE, "rb").read())

def in_cf(ip, nets):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nets if n.version == a.version)

# --- robots / ads parse --------------------------------------------------------------------------------
def parse_robots(txt):
    """Skupiny dle RFC 9309: po sobě jdoucí User-agent řádky tvoří jednu skupinu; více skupin téhož tokenu se slučuje;
    tokeny bez ohledu na velikost písmen; BOM se odstraní; 'Disallow:/' bez mezery se čte správně (split na první ':')."""
    txt = txt.lstrip("\ufeff")
    groups, cur, last_was_ua = {}, [], False
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line: continue
        k, v = [s.strip() for s in line.split(":", 1)]
        k = k.lower()
        if k == "user-agent":
            tok = v.lower()
            cur = (cur + [tok]) if last_was_ua else [tok]   # více UA řádků za sebou = jedna skupina
            groups.setdefault(tok, []); last_was_ua = True
        elif k in ("disallow", "allow", "content-signal"):
            for u in (cur or ["*"]): groups.setdefault(u, []).append((k, v))
            last_was_ua = False
        else:
            last_was_ua = False
    return groups

def _rule_matches_root(pattern):
    """Délka shody pravidla s cestou '/' (0 = neshoda). '/' → 1; '/*' → 2 (wildcard); '' = žádné omezení → 0."""
    p = pattern.strip()
    if p == "": return 0
    if p == "/": return 1
    if p == "/*" or p == "/*$" or p == "/$": return 2
    return 0

def stance(groups, bot):
    """blocked ⇔ pro skupinu jmenující token platí, že nejdelší shodné pravidlo pro '/' je Disallow (Allow vyhrává při shodě délky, RFC 9309).
    partial = jiná Disallow pravidla (ne kořen) · allowed = skupina bez Disallow · unaddressed = token nikde nejmenován (dědění z '*' se hlásí zvlášť)."""
    g = groups.get(bot.lower())
    if g is None: return "unaddressed"
    best_allow = max([_rule_matches_root(v) for k, v in g if k == "allow"] or [0])
    best_dis = max([_rule_matches_root(v) for k, v in g if k == "disallow"] or [0])
    if best_dis and best_dis > best_allow: return "blocked"
    if any(k == "disallow" and v.strip() and _rule_matches_root(v) == 0 for k, v in g): return "partial"   # jen pravidla mimo kořen
    return "allowed"   # včetně Disallow: / přebitého Allow: / (RFC 9309: při shodě délky vyhrává Allow)

ROBOTS_CASES = [  # pozitivní kontrola parseru (CHARTER §3); `python3 scripts/cfprobe.py robotstest`
    ("User-agent: GPTBot\nDisallow: /", "GPTBot", "blocked"),
    ("user-agent: gptbot\ndisallow:/", "GPTBot", "blocked"),
    ("\ufeffUser-agent: GPTBot\nDisallow: /*", "GPTBot", "blocked"),
    ("User-agent: GPTBot\nDisallow: /\nAllow: /", "GPTBot", "allowed"),
    ("User-agent: GPTBot\nDisallow: /private/", "GPTBot", "partial"),
    ("User-agent: GPTBot\nDisallow:", "GPTBot", "allowed"),
    ("User-agent: *\nDisallow: /", "GPTBot", "unaddressed"),
    ("User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /", "ClaudeBot", "blocked"),
    ("User-agent: GPTBot\nDisallow: /a\n\nUser-agent: GPTBot\nDisallow: /", "GPTBot", "blocked"),
    ("User-agent: GPTBot # trénink\nDisallow: / # vše", "GPTBot", "blocked"),
]
def cmd_robotstest(a=None):
    bad = 0
    for txt, bot, exp in ROBOTS_CASES:
        got = stance(parse_robots(txt), bot)
        print(f"  {'ok ' if got == exp else 'CHYBA'} {bot:10} očekáváno {exp:11} → {got:11} | {txt[:50]!r}"); bad += got != exp
    print("ROBOTSTEST", "SPLNĚN" if not bad else f"SELHAL ({bad})"); sys.exit(0 if not bad else 2)

def is_text_response(r):
    ct = (r.headers.get("content-type") or "").lower()
    return r.status_code == 200 and "html" not in ct and "<html" not in r.text[:2000].lower()

# --- blob store ----------------------------------------------------------------------------------------
class Store:
    def __init__(self, db, run_id):
        self.db, self.run_id, self.cctx = db, run_id, zstandard.ZstdCompressor(level=9)
        self.lock = asyncio.Lock()
    async def put(self, data: bytes, mime: str):
        if not data: return None
        h = sha256(data)
        async with self.lock:
            if not self.db.execute("SELECT 1 FROM blobs WHERE sha256=?", (h,)).fetchone():
                self.db.execute("INSERT INTO blobs VALUES (?,?,?,?,?)", (h, self.cctx.compress(data), len(data), mime, self.run_id))
        return h
    async def exec(self, sql, params):
        async with self.lock:
            self.db.execute(sql, params)

# --- DNS -----------------------------------------------------------------------------------------------
def dns_lookup(domain, resolver_ip, nets):
    res = dns.resolver.Resolver(configure=(resolver_ip is None))
    if resolver_ip: res.nameservers = [resolver_ip]
    res.lifetime = 6
    out = {"ns": [], "a": [], "aaaa": [], "error": None}
    for rt in ("NS", "A", "AAAA"):
        try: out[rt.lower()] = sorted(str(r).rstrip(".") for r in res.resolve(domain, rt))
        except dns.resolver.NoAnswer: pass
        except Exception as e:
            if rt == "A": out["error"] = type(e).__name__
    cn = {}
    for name in (domain, "www." + domain):
        try: cn[name] = [str(r.target).rstrip(".") for r in res.resolve(name, "CNAME")]
        except Exception: pass
    out["cname"] = cn
    ips = out["a"] + out["aaaa"]
    out["ns_cf"] = int(any(n.endswith("ns.cloudflare.com") for n in out["ns"]))
    out["ip_cf"] = int(bool(ips) and all(in_cf(ip, nets) for ip in ips))
    return out

# --- HTTP příčka ---------------------------------------------------------------------------------------
def new_client():
    """Jeden klient = jeden požadavek: žádné cookies mezi příčkami ani doménami, vlastní TLS spojení.
    (v4: sdílený klient střádal cookies z 15 000 domén → O(N) na požadavek, CPU 100 %; navíc přenášel cookies mezi příčkami.)"""
    return httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(15, connect=8), http2=False)

async def http_fetch(client, url, ua, browser_like):
    hdrs = {"User-Agent": ua}
    if browser_like: hdrs.update(BROWSER_HDRS)
    t0 = time.time()
    try:
        async with new_client() as c:
            r = await c.get(url, headers=hdrs)
            r.read()
        first = r.history[0] if r.history else r          # první odpověď na https://{d}/ (Opus N3)
        body = r.content[:2_000_000]
        text = r.text[:600_000] if "html" in (r.headers.get("content-type") or "").lower() or url.endswith("/") else r.text[:200_000]
        title = (re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S) or [None, ""])[1]
        title = re.sub(r"\s+", " ", title).strip()[:200] if title else ""
        challenge = int(bool(CHALLENGE_RE.search(title) or CHALLENGE_RE.search(text[:5000]) or (r.headers.get("cf-mitigated") == "challenge")))
        ok = int(200 <= r.status_code < 400 and not challenge)
        in_host = httpx.URL(url).host
        return {"resp": r, "status": r.status_code, "url_final": str(r.url), "host_final": r.url.host, "title": title,
                "challenge": challenge, "pass": ok, "body": body, "text": text, "elapsed_ms": int((time.time() - t0) * 1000),
                "headers": {k.lower(): v for k, v in r.headers.items()}, "error": None,
                "cf_ray_first": first.headers.get("cf-ray"), "status_first": first.status_code,
                "foreign_redirect": int(reg_domain(r.url.host) != reg_domain(in_host)), "block_sig": block_signature(title, text)}
    except Exception as e:
        return {"resp": None, "status": None, "url_final": None, "host_final": None, "title": "", "challenge": 0, "pass": 0,
                "body": b"", "text": "", "elapsed_ms": int((time.time() - t0) * 1000), "headers": {}, "error": type(e).__name__,
                "cf_ray_first": None, "status_first": None, "foreign_redirect": None, "block_sig": None}

async def capped_get(client, url, ua, browser_like, cap=EXTRA_CAP):
    """GET s limitem velikosti těla (sitemapy bývají velké); vrací (status, content_type, bytes, error)."""
    hdrs = {"User-Agent": ua}
    if browser_like: hdrs.update(BROWSER_HDRS)
    try:
        async with new_client() as c, c.stream("GET", url, headers=hdrs) as r:
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) >= cap: break
            return r.status_code, (r.headers.get("content-type") or ""), bytes(buf[:cap]), None
    except Exception as e:
        return None, "", b"", type(e).__name__

# --- Chrome příčky (L0 = člověk, L1 = headless z krabice) — samostatné worker procesy -------------------
# Proč procesy: Playwright ve sdílené asyncio smyčce nedokončí zrušení úlohy, takže wait_for deadliny nevystřelí
# (T0a r2, 2026-09-14). Worker = sync Playwright, JSON řádky na stdin/stdout; při překročení PAGE_DEADLINE ho rodič zabije.
CHROME_WORKER_JOBS = 150   # po tolika stránkách se worker vymění (úniky paměti Chrome)

def chrome_worker_main():
    """Běží v subprocesu: čte {"rung","url"} řádky, vrací JSON výsledek. Nikdy nesmí spadnout potichu."""
    from playwright.sync_api import sync_playwright
    out = sys.stdout
    with sync_playwright() as pw:
        b0 = pw.chromium.launch(headless=True, executable_path=CHROME_BIN, args=["--headless=new", "--disable-blink-features=AutomationControlled"] + CONTAINER_ARGS)
        b1 = pw.chromium.launch(headless=True, executable_path=CHROME_BIN, args=["--headless=new"] + CONTAINER_ARGS)
        out.write(json.dumps({"ready": True}) + "\n"); out.flush()
        for line in sys.stdin:
            try: job = json.loads(line)
            except Exception: continue
            rung, url = job["rung"], job["url"]; t0 = time.time()
            if rung == "RAW":   # textový soubor přes prohlížeč (fallback, když hrana nepustí HTTP knihovnu)
                ctx = b0.new_context(locale="cs-CZ", user_agent=CHROME_UA, viewport={"width": 1366, "height": 768})
                ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
                page = ctx.new_page(); res = None
                try:
                    resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    page.wait_for_timeout(1500)
                    status = resp.status if resp else None
                    ct = (resp.headers.get("content-type") if resp else "") or ""
                    try: body = page.evaluate("document.body ? document.body.innerText : ''")
                    except Exception: body = ""
                    title = (page.title() or "")[:200]
                    challenge = int(bool(CHALLENGE_RE.search(title) or (resp and resp.headers.get("cf-mitigated") == "challenge")))
                    res = {"status": status, "content_type": ct, "body": body, "title": title, "challenge": challenge, "error": None}
                except Exception as e:
                    res = {"status": None, "content_type": "", "body": "", "title": "", "challenge": 0, "error": type(e).__name__}
                finally:
                    try: ctx.close()
                    except Exception: pass
                res["elapsed_ms"] = int((time.time() - t0) * 1000)
                out.write(json.dumps(res) + "\n"); out.flush(); continue
            if rung == "L0":
                ctx = b0.new_context(locale="cs-CZ", user_agent=CHROME_UA, viewport={"width": 1366, "height": 768})
                ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
            else:
                ctx = b1.new_context(locale="cs-CZ")
            page = ctx.new_page(); res = None
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(3000)
                html = page.content(); title = (page.title() or "")[:200]
                try: text_len = len(page.evaluate("document.body ? document.body.innerText : ''"))
                except Exception: text_len = 0
                status = resp.status if resp else None
                hdrs = {k.lower(): v for k, v in (resp.all_headers() if resp else {}).items()}
                challenge = int(bool(CHALLENGE_RE.search(title) or hdrs.get("cf-mitigated") == "challenge" or CHALLENGE_RE.search(html[:5000])))
                ok = int(status is not None and 200 <= status < 400 and not challenge and text_len > 0)
                res = {"status": status, "url_final": page.url, "host_final": httpx.URL(page.url).host, "title": title, "text_len": text_len,
                       "challenge": challenge, "pass": ok, "body": html, "headers": hdrs, "error": None}
            except Exception as e:
                res = {"status": None, "url_final": None, "host_final": None, "title": "", "text_len": 0, "challenge": 0, "pass": 0,
                       "body": "", "headers": {}, "error": type(e).__name__}
            finally:
                try: ctx.close()
                except Exception: pass
            res["elapsed_ms"] = int((time.time() - t0) * 1000)
            out.write(json.dumps(res) + "\n"); out.flush()

class ChromeWorker:
    def __init__(self): self.proc = None; self.jobs = 0
    async def start(self):
        env = dict(os.environ, CFPROBE_CHROME_WORKER="1")
        self.proc = await asyncio.create_subprocess_exec(sys.executable, os.path.abspath(__file__), "chromeworker", stdin=asyncio.subprocess.PIPE,
                                                         stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env, limit=8_000_000)
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=60)
        if not line or not json.loads(line).get("ready"): raise RuntimeError("chrome worker nenastartoval")
        self.jobs = 0
    async def kill(self):
        if self.proc and self.proc.returncode is None:
            try: self.proc.kill()
            except ProcessLookupError: pass
            try: await asyncio.wait_for(self.proc.wait(), timeout=10)
            except Exception: pass
        self.proc = None
    async def run(self, rung, url):
        """Jedna stránka s tvrdým limitem: při překročení PAGE_DEADLINE se worker zabije a nahradí."""
        if self.proc is None or self.proc.returncode is not None: await self.start()
        try:
            self.proc.stdin.write((json.dumps({"rung": rung, "url": url}) + "\n").encode()); await self.proc.stdin.drain()
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=PAGE_DEADLINE)
            if not line: raise RuntimeError("worker zemřel")
            r = json.loads(line); r["body"] = r["body"].encode() if isinstance(r.get("body"), str) else r.get("body", b""); self.jobs += 1
            if self.jobs >= CHROME_WORKER_JOBS: await self.kill()
            return r
        except asyncio.TimeoutError:
            await self.kill()
            return {"status": None, "url_final": None, "host_final": None, "title": "", "text_len": 0, "challenge": 0, "pass": 0,
                    "body": b"", "headers": {}, "error": "PageDeadline", "elapsed_ms": int(PAGE_DEADLINE * 1000)}
        except Exception as e:
            await self.kill()
            return {"status": None, "url_final": None, "host_final": None, "title": "", "text_len": 0, "challenge": 0, "pass": 0,
                    "body": b"", "headers": {}, "error": "Worker" + type(e).__name__, "elapsed_ms": 0}

class Browsers:
    """Pool Chrome workerů; fetch() si vezme volného workera. restarts = počet výměn (kill) pro sidecar."""
    def __init__(self, n): self.n = n; self.free = asyncio.Queue(); self.workers = []; self.restarts = 0
    async def start(self):
        for _ in range(self.n):
            w = ChromeWorker(); await w.start(); self.workers.append(w); self.free.put_nowait(w)
    async def fetch(self, rung, url):
        w = await self.free.get()
        try:
            before = w.proc
            r = await w.run(rung, url)
            if w.proc is not before: self.restarts += 1
            return r
        finally:
            self.free.put_nowait(w)
    async def stop(self):
        for w in self.workers: await w.kill()

# --- jedna doména ----------------------------------------------------------------------------------------
async def probe_domain(domain, cc, stratum, run_id, store, client, browsers, nets, resolvers, rng, http_sem, chrome_sem, delay):
    url = f"https://{domain}/"
    # DNS dvěma cestami
    dns_rows = {}
    for label, rip in resolvers.items():
        d = await asyncio.to_thread(dns_lookup, domain, rip, nets)
        dns_rows[label] = d
        await store.exec("INSERT OR REPLACE INTO dns(run_id,domain,resolver,ns_json,a_json,aaaa_json,ns_cf,ip_cf,error,cname_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (run_id, domain, label, json.dumps(d["ns"]), json.dumps(d["a"]), json.dumps(d["aaaa"]), d["ns_cf"], d["ip_cf"], d["error"], json.dumps(d.get("cname", {}))))
    primary = dns_rows["system"]
    mismatch = int(any((dns_rows[k]["ip_cf"], dns_rows[k]["ns_cf"]) != (primary["ip_cf"], primary["ns_cf"]) for k in dns_rows))
    unreachable = int(not (primary["a"] or primary["aaaa"]))

    hdr_cf, text_len = {}, {}
    rungs = HTTP_RUNGS_BASE + ["robots", "ads", "extra"]
    rng.shuffle(rungs)
    rungs.append("L5")   # v6.2: nová příčka za stávající sadou (RFC 18. 9.), Q8 se počítá bez ní
    rungs.append("L6")   # v6.3: OAI-SearchBot za L5 (RFC 23. 9.)
    if domain in HOLDOUT: rungs = [r for r in rungs if r not in HOLDOUT_EXCLUDE]   # v6.3 holdout
    robots_txt, robots_via, robots_status, robots_sha, robots_is_text = "", None, None, None, 0
    ads_txt, ads_via, ads_status, ads_sha = "", None, None, None
    html_l2, l2_pass, l0_pass = "", 0, 0
    connect_fails, skipped = 0, False
    pending_raw = []   # (co, url) pro Chrome fallback, když hrana nepustí HTTP knihovnu
    robots_unobs, ads_unobs = 0, 0
    async with http_sem:
        for rung in rungs:
            if unreachable: break
            if connect_fails >= 2:   # dvě selhání spojení za sebou = host neodpovídá; zbytek se zapíše jako skipped_unreachable
                skipped = True
                if rung in HTTP_RUNGS:
                    await store.exec("INSERT OR REPLACE INTO fetch(run_id,domain,rung,url,url_final,host_final,status,cf_mitigated,cf_ray,server,content_type,title,text_len,challenge,pass,elapsed_ms,error,headers_sha,body_sha,ts,cf_ray_first,status_first,foreign_redirect,block_sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (run_id, domain, rung, url, None, None, None, None, None, None, None, "", 0, 0, 0, 0, "skipped_unreachable", None, None, now(), None, None, None, None))
                continue
            if rung == "robots":
                # definice v6: první úspěšná cesta L3 → L2 → RAW (Chrome); když všechny skončí 403/429/challenge → unobservable (Opus N16)
                blocked_all = True
                for via in ("L3", "L2"):
                    r = await http_fetch(client, f"https://{domain}/robots.txt", UA[via], via == "L2")
                    robots_status, robots_via = r["status"], via
                    if r["resp"] is not None and r["status"] == 200 and not r["challenge"]:
                        robots_is_text = int(is_text_response(r["resp"])); robots_txt = r["text"] if robots_is_text else ""
                        robots_sha = await store.put(r["body"], "text/plain"); blocked_all = False; break
                    if not (r["status"] in (403, 429, None) or r["challenge"]): blocked_all = False; break   # 404 apod. = pozorováno
                    await asyncio.sleep(delay)
                if blocked_all: pending_raw.append(("robots", f"https://{domain}/robots.txt"))
            elif rung == "extra":
                for path in EXTRA_PATHS:
                    st, ct, body, err = await capped_get(client, f"https://{domain}{path}", UA["L3"], False)
                    via = "L3"
                    if st in (403, 429, None) or (st == 200 and CHALLENGE_RE.search(body[:5000].decode(errors="ignore"))):
                        await asyncio.sleep(delay)
                        st, ct, body, err = await capped_get(client, f"https://{domain}{path}", UA["L2"], True); via = "L2"
                    ok = st == 200 and not CHALLENGE_RE.search(body[:5000].decode(errors="ignore"))
                    is_text = int(ok and "html" not in ct.lower() and b"<html" not in body[:2000].lower())
                    bsha = await store.put(body, ct.split(";")[0] or "application/octet-stream") if ok and is_text else None
                    unobs = int(st in (403, 429, None) or bool(CHALLENGE_RE.search(body[:5000].decode(errors="ignore"))))
                    if unobs: pending_raw.append(("extra:" + path, f"https://{domain}{path}"))
                    await store.exec("INSERT OR REPLACE INTO extra(run_id,domain,path,via,status,content_type,size,is_text,body_sha,unobservable) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                     (run_id, domain, path, via, st, ct[:80], len(body), is_text, bsha, unobs))
                    await asyncio.sleep(delay)
            elif rung == "ads":
                blocked_all = True
                for via in ("L3", "L2"):
                    r = await http_fetch(client, f"https://{domain}/ads.txt", UA[via], via == "L2")
                    ads_status, ads_via = r["status"], via
                    if r["resp"] is not None and r["status"] == 200 and not r["challenge"]:
                        if is_text_response(r["resp"]): ads_txt = r["text"]; ads_sha = await store.put(r["body"], "text/plain")
                        blocked_all = False; break
                    if not (r["status"] in (403, 429, None) or r["challenge"]): blocked_all = False; break
                    await asyncio.sleep(delay)
                if blocked_all: pending_raw.append(("ads", f"https://{domain}/ads.txt"))
            else:
                r = await http_fetch(client, url, UA[rung], rung == "L2")
                hsha = await store.put(json.dumps(r["headers"]).encode(), "application/json")
                bsha = await store.put(r["body"], "text/html")   # v6: těla všech HTTP příček (pass2 z blobů, Opus N11)
                if rung == "L2": html_l2 = r["text"]; hdr_cf = r["headers"]; l2_pass = r["pass"]
                connect_fails = connect_fails + 1 if r["error"] in ("ConnectError", "ConnectTimeout") else 0
                await store.exec("INSERT OR REPLACE INTO fetch(run_id,domain,rung,url,url_final,host_final,status,cf_mitigated,cf_ray,server,content_type,title,text_len,challenge,pass,elapsed_ms,error,headers_sha,body_sha,ts,cf_ray_first,status_first,foreign_redirect,block_sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, domain, rung, url, r["url_final"], r["host_final"], r["status"], r["headers"].get("cf-mitigated"),
                     r["headers"].get("cf-ray"), r["headers"].get("server"), r["headers"].get("content-type"), r["title"],
                     len(r["text"]), r["challenge"], r["pass"], r["elapsed_ms"], r["error"], hsha, bsha, now(),
                     r.get("cf_ray_first"), r.get("status_first"), r.get("foreign_redirect"), r.get("block_sig")))
            await asyncio.sleep(delay)

    # Chrome příčky
    html_l0 = ""
    if not unreachable and not skipped and browsers:
        async with chrome_sem:
            for rung in ("L0", "L1"):
                r = await browsers.fetch(rung, url)
                hsha = await store.put(json.dumps(r["headers"]).encode(), "application/json")
                bsha = await store.put(r["body"], "text/html") if rung == "L0" else None
                if rung == "L0": html_l0 = r["body"].decode(errors="replace"); text_len["L0"] = r["text_len"]; l0_pass = r["pass"]
                await store.exec("INSERT OR REPLACE INTO fetch(run_id,domain,rung,url,url_final,host_final,status,cf_mitigated,cf_ray,server,content_type,title,text_len,challenge,pass,elapsed_ms,error,headers_sha,body_sha,ts,cf_ray_first,status_first,foreign_redirect,block_sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, domain, rung, url, r["url_final"], r["host_final"], r["status"], r["headers"].get("cf-mitigated"),
                     r["headers"].get("cf-ray"), r["headers"].get("server"), r["headers"].get("content-type"), r["title"],
                     r["text_len"], r["challenge"], r["pass"], r["elapsed_ms"], r["error"], hsha, bsha, now(),
                     None, None, int(reg_domain(r["host_final"]) != reg_domain(domain)) if r["host_final"] else None, block_signature(r["title"], r["body"].decode(errors="replace")[:8000])))
                await asyncio.sleep(delay)
            for what, raw_url in pending_raw:   # fallback přes prohlížeč (Opus N16)
                rr = await browsers.fetch("RAW", raw_url)
                got = rr.get("status") == 200 and not rr.get("challenge") and not rr.get("error")
                body = rr["body"] if got else b""
                if what == "robots":
                    robots_status, robots_via = rr.get("status"), "L0"
                    if got: robots_txt = body.decode(errors="replace"); robots_is_text = 1; robots_sha = await store.put(body, "text/plain")
                    else: robots_unobs = 1
                elif what == "ads":
                    ads_status, ads_via = rr.get("status"), "L0"
                    if got: ads_txt = body.decode(errors="replace"); ads_sha = await store.put(body, "text/plain")
                    else: ads_unobs = 1
                else:
                    path = what.split(":", 1)[1]
                    bsha = await store.put(body, "text/plain") if got else None
                    await store.exec("INSERT OR REPLACE INTO extra(run_id,domain,path,via,status,content_type,size,is_text,body_sha,unobservable) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                     (run_id, domain, path, "L0", rr.get("status"), (rr.get("content_type") or "")[:80], len(body), int(got), bsha, int(not got)))
                await asyncio.sleep(delay)

    # robots / ads vyhodnocení
    g = parse_robots(robots_txt)
    st = {b: stance(g, b) for b in AI_BOTS}
    csig = (re.search(r"^content-signal:\s*(.+)$", robots_txt, re.I | re.M) or [None, None])[1]
    await store.exec("INSERT OR REPLACE INTO robots(run_id,domain,via,status,body_sha,is_text,cf_managed,content_signal,stances_json,star_blocked,ai_blocked_n,train_blocked,unobservable) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, domain, robots_via, robots_status, robots_sha, robots_is_text, int("begin cloudflare managed content" in robots_txt.lower()),
         csig, json.dumps(st), int(stance(g, "*") == "blocked"), sum(v == "blocked" for v in st.values()),
         int(any(st[b] == "blocked" for b in TRAIN_BOTS)), robots_unobs))
    sigs = {k: bool(re.search(p, html_l2 or html_l0, re.I)) for k, p in AD_SIGS.items()}
    await store.exec("INSERT OR REPLACE INTO ads(run_id,domain,via,status,body_sha,valid_lines,html_sigs_json,html_ads,unobservable) VALUES (?,?,?,?,?,?,?,?,?)",
        (run_id, domain, ads_via, ads_status, ads_sha, len(ADS_LINE_RE.findall(ads_txt)), json.dumps(sigs), int(any(sigs.values())), ads_unobs))

    # souhrn domény
    hdr_is_cf = int(bool(hdr_cf.get("cf-ray")) or (hdr_cf.get("server") or "").lower() == "cloudflare")
    if primary["ip_cf"] or hdr_is_cf: cf_class = "cf_proxied"
    elif primary["ns_cf"]: cf_class = "cf_dns_only"
    else: cf_class = "no_cf"
    if unreachable: cf_class = "unresolved"
    # JS-závislost = text po renderu (L0) / text bez JS (L2); jen když obě příčky prošly, jinak None
    l2_text = len(re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_l2, flags=re.S | re.I)))
    js_dep = (text_len["L0"] / l2_text) if (l2_text and text_len.get("L0") and l2_pass and l0_pass) else None
    reachable = int((not unreachable) and (not skipped) and (l2_pass or l0_pass or bool(html_l2) or bool(html_l0)))
    cn = primary.get("cname", {}); cname_targets = [t for v in cn.values() for t in v]
    cname_foreign = int(any(reg_domain(t) != reg_domain(domain) for t in cname_targets)) if cname_targets else 0
    await store.exec("INSERT OR REPLACE INTO domain_summary(run_id,domain,cc,stratum,cf_class,ns_cf,ip_cf,hdr_cf,resolver_mismatch,unreachable,llms_txt,jsonld,js_dep_ratio,reachable,cname_foreign) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, domain, cc, stratum, cf_class, primary["ns_cf"], primary["ip_cf"], hdr_is_cf, mismatch, unreachable,
         int(bool(re.search(r"llms\.txt", html_l0 or html_l2, re.I))), int(bool(re.search(r"application/ld\+json", html_l0 or html_l2, re.I))), js_dep, reachable, cname_foreign))
    return cf_class

# --- run ------------------------------------------------------------------------------------------------
async def cmd_run(a):
    if git_dirty() and not a.allow_dirty:
        sys.exit("FATÁLNÍ: scripts/cfprobe.py má necommitnuté změny — měřidlo bez rodokmenu neměří (nebo --allow-dirty jen pro selftest)")
    db = open_db(a.db)
    if db.execute("SELECT 1 FROM runs WHERE run_id=?", (a.run_id,)).fetchone():
        sys.exit(f"FATÁLNÍ: run-id {a.run_id} už existuje — runy se nepřepisují (exit 2)") if True else None
    nets, cf_sha = load_cf_ranges()
    pop_bytes = open(a.population, "rb").read()
    if getattr(a, "holdout", None):
        HOLDOUT.update((l.strip().split(",")[0]) for l in open(a.holdout) if l.strip() and not l.startswith("#"))
        a.notes = (a.notes or "") + f" | holdout {os.path.basename(a.holdout)} n={len(HOLDOUT)} sha={hashlib.sha256(open(a.holdout, 'rb').read()).hexdigest()[:12]}"
    # formát populace: "doména" | "rank,doména" | "rank,doména,cc,stratum"
    entries = []
    for l in pop_bytes.decode().splitlines():
        if not l.strip() or l.startswith("#"): continue
        f = [x.strip() for x in l.split(",")]
        if len(f) == 1: entries.append((None, f[0], None, None))
        elif len(f) == 2: entries.append((int(f[0]), f[1], None, None))
        else: entries.append((int(f[0]), f[1], f[2], f[3] if len(f) > 3 else None))
    pop_id = os.path.basename(a.population)
    for r, d, cc, st in entries:
        db.execute("INSERT OR IGNORE INTO population VALUES (?,?,?,?,?,?)", (pop_id, d, r, "tranco", cc, st))
    if a.limit: entries = entries[:a.limit]
    domains = [e[1] for e in entries]
    rng = random.Random(a.seed); order = entries[:]; rng.shuffle(order)
    try: egress = httpx.get("https://api.ipify.org", timeout=10).text.strip()
    except Exception: egress = None
    try: org = httpx.get(f"https://ipinfo.io/{egress}/json", timeout=10).json().get("org")
    except Exception: org = None
    try: chrome_v = subprocess.run([CHROME_BIN, "--version"], capture_output=True, text=True).stdout.strip() + (" [container:no-sandbox]" if CONTAINER_ARGS else "")
    except Exception: chrome_v = None
    resolvers = {"system": None, "google": "[IP odstraněna]"}
    db.execute("INSERT INTO runs(run_id,kind,started,script_commit,script_sha,population_file,population_sha,cf_ips_sha,egress_ip,egress_org,"
               "resolvers,chrome_version,httpx_version,python_version,seed,ua_json,n_domains,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (a.run_id, a.kind, now(), git_commit(), sha256(open(__file__, "rb").read()), pop_id, sha256(pop_bytes), cf_sha, egress, org,
                json.dumps(resolvers), chrome_v, httpx.__version__, sys.version.split()[0], a.seed,
                json.dumps({"L0": CHROME_UA, **UA, "_L0_params": {"viewport": "1366x768", "locale": "cs-CZ", "wait_after_domcontentloaded_ms": 3000, "goto_timeout_ms": 20000, "page_deadline_s": PAGE_DEADLINE, "webdriver_hidden": True, "chrome_args": ["--headless=new", "--disable-blink-features=AutomationControlled"] + CONTAINER_ARGS, "http_library": f"httpx {httpx.__version__}, jeden klient na požadavek, bez cookies", "block_sigs": list(BLOCK_SIGS.keys()), "pass2_min_text": PASS2_MIN_TEXT}}), len(domains), (a.notes + f" egress_label={os.environ.get('CFPROBE_EGRESS','home')}").strip()))
    db.commit()
    store = Store(db, a.run_id)
    http_sem, chrome_sem = asyncio.Semaphore(a.workers), asyncio.Semaphore(a.chrome_workers)
    browsers = None
    if not a.no_chrome:
        browsers = Browsers(a.chrome_workers); await browsers.start()
    counts, errors, t0 = {}, 0, time.time()
    client = None   # v5: klient per požadavek (new_client), viz http_fetch
    if True:
        domain_sem = asyncio.Semaphore(a.domain_slots)   # backpressure: HTTP fáze nesmí utéct Chrome fázi (T0a 14. 9.: 12 000 domén ve frontě, 21 GB RAM)
        async def one(e):
            nonlocal errors
            _, d, cc, st = e
            async with domain_sem:
                try:
                    c = await asyncio.wait_for(probe_domain(d, cc, st, a.run_id, store, client, browsers, nets, resolvers, random.Random(f"{a.seed}:{d}"), http_sem, chrome_sem, a.delay), timeout=DOMAIN_DEADLINE)
                    counts[c] = counts.get(c, 0) + 1
                except asyncio.TimeoutError:
                    errors += 1; counts["deadline"] = counts.get("deadline", 0) + 1
                    await store.exec("INSERT OR REPLACE INTO domain_summary(run_id,domain,cc,stratum,cf_class,ns_cf,ip_cf,hdr_cf,resolver_mismatch,unreachable,llms_txt,jsonld,js_dep_ratio,reachable,cname_foreign) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (a.run_id, d, cc, st, "deadline", None, None, None, None, 0, None, None, None, None, None))
                    print(f"[chyba] {d}: DomainDeadline {DOMAIN_DEADLINE}s", file=sys.stderr)
                except Exception as ex:
                    errors += 1; print(f"[chyba] {d}: {type(ex).__name__}: {ex}", file=sys.stderr)
            done = sum(counts.values())
            if done % 50 == 0 or done == len(order):
                async with store.lock: db.commit()
                print(f"[{done}/{len(order)}] {int(time.time()-t0)} s  {counts}  chyb={errors}", flush=True)

        await asyncio.gather(*(one(e) for e in order))
    db.execute("UPDATE runs SET finished=?, n_errors=?, notes=notes||? WHERE run_id=?", (now(), errors, f" chrome_restarts={browsers.restarts if browsers else 0} domain_slots={a.domain_slots}", a.run_id)); db.commit()
    print(f"hotovo: {a.run_id} domén={len(order)} třídy={counts} chyb={errors} čas={int(time.time()-t0)} s", flush=True)
    if browsers:
        try: await asyncio.wait_for(browsers.stop(), timeout=30)
        except Exception as e: print(f"[varování] zastavení Chrome: {type(e).__name__}", file=sys.stderr)
    db.close()
    if not getattr(a, "_no_exit", False):
        os._exit(0)   # finished je zapsáno; případný viselec v teardownu nesmí blokovat plánovač (selftest pokračuje)

# --- export + pečeť ---------------------------------------------------------------------------------------
def q(db, sql, p=()): return db.execute(sql, p).fetchall()

def compute_summary(db, run_id, commit):
    rows = []
    def add(cls, metric, value, n): rows.append((run_id, cls, metric, value, n, commit))
    classes = ["cf_proxied", "cf_dns_only", "no_cf", "unresolved"]
    tot = q(db, "SELECT count(*) FROM domain_summary WHERE run_id=?", (run_id,))[0][0]
    for cls in classes:
        n = q(db, "SELECT count(*) FROM domain_summary WHERE run_id=? AND cf_class=?", (run_id, cls))[0][0]
        add("all", f"share_{cls}", n / tot if tot else None, tot)
    add("all", "resolver_mismatch_share", q(db, "SELECT avg(resolver_mismatch) FROM domain_summary WHERE run_id=?", (run_id,))[0][0], tot)
    ccs = [r[0] for r in q(db, "SELECT DISTINCT cc FROM domain_summary WHERE run_id=? AND cc IS NOT NULL ORDER BY cc", (run_id,))]
    scopes = [("all", "")] + [(c, f" AND s.cf_class='{c}'") for c in classes[:3]]
    for cc in ccs:
        scopes.append((f"{cc}|all", f" AND s.cc='{cc}'"))
        scopes += [(f"{cc}|{c}", f" AND s.cc='{cc}' AND s.cf_class='{c}'") for c in classes[:3]]
        n_cc = q(db, "SELECT count(*) FROM domain_summary WHERE run_id=? AND cc=?", (run_id, cc))[0][0]
        for c in classes:
            k = q(db, "SELECT count(*) FROM domain_summary WHERE run_id=? AND cc=? AND cf_class=?", (run_id, cc, c))[0][0]
            add(f"{cc}|all", f"share_{c}", k / n_cc if n_cc else None, n_cc)
    for cls, w in scopes:
        # robots
        r = q(db, f"SELECT count(*), sum(r.train_blocked), sum(r.ai_blocked_n>0), sum(r.cf_managed), sum(r.content_signal IS NOT NULL) "
                  f"FROM robots r JOIN domain_summary s USING(run_id,domain) WHERE r.run_id=? AND r.status=200 AND r.is_text=1{w}", (run_id,))[0]
        n = r[0] or 0
        add(cls, "robots_ok_n", n, n)
        add(cls, "train_block_share", (r[1] or 0) / n if n else None, n)
        add(cls, "any_ai_block_share", (r[2] or 0) / n if n else None, n)
        add(cls, "cf_managed_share", (r[3] or 0) / n if n else None, n)
        add(cls, "content_signal_share", (r[4] or 0) / n if n else None, n)
        # žebřík mezi L0 pass
        base = q(db, f"SELECT count(*) FROM fetch f JOIN domain_summary s USING(run_id,domain) WHERE f.run_id=? AND f.rung='L0' AND f.pass=1{w}", (run_id,))[0][0]
        add(cls, "L0_pass_n", base, base)
        for rung in ("L1", "L2", "L3", "L3r", "L4a", "L4b", "L4c", "L4g"):
            f = q(db, f"SELECT count(*) FROM fetch f JOIN domain_summary s USING(run_id,domain) WHERE f.run_id=? AND f.rung=? AND f.pass=0{w} "
                      f"AND EXISTS(SELECT 1 FROM fetch g WHERE g.run_id=f.run_id AND g.domain=f.domain AND g.rung='L0' AND g.pass=1)", (run_id, rung))[0][0]
            add(cls, f"{rung}_fail_share_given_L0pass", f / base if base else None, base)
        ai_spec = q(db, f"SELECT count(*) FROM fetch f JOIN domain_summary s USING(run_id,domain) WHERE f.run_id=? AND f.rung='L4a' AND f.pass=0{w} "
                        f"AND EXISTS(SELECT 1 FROM fetch g WHERE g.run_id=f.run_id AND g.domain=f.domain AND g.rung='L0' AND g.pass=1) "
                        f"AND EXISTS(SELECT 1 FROM fetch h WHERE h.run_id=f.run_id AND h.domain=f.domain AND h.rung='L3' AND h.pass=1)", (run_id,))[0][0]
        add(cls, "ai_specific_share_given_L0pass", ai_spec / base if base else None, base)
        gb_spec = q(db, f"SELECT count(*) FROM fetch f JOIN domain_summary s USING(run_id,domain) WHERE f.run_id=? AND f.rung='L4a' AND f.pass=0{w} "
                        f"AND EXISTS(SELECT 1 FROM fetch g WHERE g.run_id=f.run_id AND g.domain=f.domain AND g.rung='L0' AND g.pass=1) "
                        f"AND EXISTS(SELECT 1 FROM fetch h WHERE h.run_id=f.run_id AND h.domain=f.domain AND h.rung='L4g' AND h.pass=1)", (run_id,))[0][0]
        add(cls, "L4a_fail_L4g_pass_share_given_L0pass", gb_spec / base if base else None, base)
        # monetizace
        ads = q(db, f"SELECT count(*), sum(a.valid_lines>0), sum(a.html_ads) FROM ads a JOIN domain_summary s USING(run_id,domain) "
                    f"WHERE a.run_id=? {w} AND EXISTS(SELECT 1 FROM fetch g WHERE g.run_id=a.run_id AND g.domain=a.domain AND g.rung='L0' AND g.pass=1)", (run_id,))[0]
        add(cls, "ads_txt_share_given_L0pass", (ads[1] or 0) / ads[0] if ads[0] else None, ads[0])
        add(cls, "html_ads_share_given_L0pass", (ads[2] or 0) / ads[0] if ads[0] else None, ads[0])
        # bonus
        b = q(db, f"SELECT count(*), sum(s.llms_txt), sum(s.jsonld), avg(s.js_dep_ratio) FROM domain_summary s WHERE s.run_id=? AND s.unreachable=0{w}", (run_id,))[0]
        add(cls, "llms_txt_mention_share", (b[1] or 0) / b[0] if b[0] else None, b[0])
        add(cls, "jsonld_share", (b[2] or 0) / b[0] if b[0] else None, b[0])
        add(cls, "js_dep_ratio_mean", b[3], b[0])
        for path in EXTRA_PATHS:
            e = q(db, f"SELECT count(*), sum(x.status=200 AND x.is_text=1) FROM extra x JOIN domain_summary s USING(run_id,domain) WHERE x.run_id=? AND x.path=? AND s.unreachable=0{w}", (run_id, path))[0]
            add(cls, f"exists_{path.strip('/').replace('/', '_')}_share", (e[1] or 0) / e[0] if e[0] else None, e[0])
    db.executemany("INSERT OR REPLACE INTO summary VALUES (?,?,?,?,?,?)", rows)
    return rows

def cmd_export(a):
    db = open_db(a.db)
    run = db.execute("SELECT * FROM runs WHERE run_id=?", (a.run_id,)).fetchone()
    if not run: sys.exit("FATÁLNÍ: run neexistuje")
    cols = [c[1] for c in db.execute("PRAGMA table_info(runs)")]
    run = dict(zip(cols, run))
    if not run["finished"]: sys.exit("FATÁLNÍ: run nedoběhl (finished IS NULL) — nepečetí se")
    commit = git_commit()
    rows = compute_summary(db, a.run_id, commit)
    if not run["sealed_at"]:
        db.execute("UPDATE runs SET sealed_at=? WHERE run_id=?", (now(), a.run_id))
    db.commit()
    run = dict(zip(cols, db.execute("SELECT * FROM runs WHERE run_id=?", (a.run_id,)).fetchone()))
    os.makedirs(a.out, exist_ok=True)
    files = {}
    files["sidecar.prov.json"] = json.dumps(run, ensure_ascii=False, indent=1).encode()
    # results.jsonl
    lines = []
    fcols = [c[1] for c in db.execute("PRAGMA table_info(fetch)")]
    for (domain,) in db.execute("SELECT domain FROM domain_summary WHERE run_id=? ORDER BY domain", (a.run_id,)):
        s = dict(zip([c[1] for c in db.execute("PRAGMA table_info(domain_summary)")], db.execute("SELECT * FROM domain_summary WHERE run_id=? AND domain=?", (a.run_id, domain)).fetchone()))
        r = db.execute("SELECT via,status,body_sha,is_text,cf_managed,content_signal,stances_json,star_blocked,ai_blocked_n,train_blocked FROM robots WHERE run_id=? AND domain=?", (a.run_id, domain)).fetchone()
        ad = db.execute("SELECT via,status,body_sha,valid_lines,html_sigs_json,html_ads FROM ads WHERE run_id=? AND domain=?", (a.run_id, domain)).fetchone()
        fe = {row[2]: {"status": row[6], "pass": row[14], "challenge": row[13], "cf_mitigated": row[7], "host_final": row[5], "title": row[11], "headers_sha": row[17], "body_sha": row[18], "error": row[16]}
              for row in db.execute("SELECT * FROM fetch WHERE run_id=? AND domain=?", (a.run_id, domain))}
        s.pop("run_id", None)
        s["robots"] = dict(zip(["via", "status", "body_sha", "is_text", "cf_managed", "content_signal", "stances", "star_blocked", "ai_blocked_n", "train_blocked"], r)) if r else None
        if s["robots"]: s["robots"]["stances"] = json.loads(s["robots"]["stances"])
        s["ads"] = dict(zip(["via", "status", "body_sha", "valid_lines", "html_sigs", "html_ads"], ad)) if ad else None
        if s["ads"]: s["ads"]["html_sigs"] = json.loads(s["ads"]["html_sigs"])
        s["fetch"] = fe
        s["extra"] = {row[0]: {"via": row[1], "status": row[2], "content_type": row[3], "size": row[4], "is_text": row[5], "body_sha": row[6]}
                      for row in db.execute("SELECT path,via,status,content_type,size,is_text,body_sha FROM extra WHERE run_id=? AND domain=?", (a.run_id, domain))}
        lines.append(json.dumps(s, ensure_ascii=False))
    files["results.jsonl"] = ("\n".join(lines) + "\n").encode()
    files["summary.json"] = json.dumps([{"cf_class": r[1], "metric": r[2], "value": r[3], "n": r[4]} for r in rows], ensure_ascii=False, indent=1).encode()
    for name, data in files.items():
        open(os.path.join(a.out, name), "wb").write(data)
    # parquet (analytická vrstva) — vedle DB, mimo git
    pq_dir = os.path.join(os.path.dirname(os.path.abspath(a.db)), "parquet", a.run_id); os.makedirs(pq_dir, exist_ok=True)
    try:
        import duckdb
        c = duckdb.connect(); c.execute("INSTALL sqlite; LOAD sqlite;"); c.execute(f"ATTACH '{a.db}' AS raw (TYPE sqlite, READ_ONLY)")
        for t in ("fetch", "dns", "robots", "ads", "extra", "domain_summary", "summary", "derived"):
            c.execute(f"COPY (SELECT * FROM raw.{t} WHERE run_id='{a.run_id}') TO '{os.path.join(pq_dir, t + '.parquet')}' (FORMAT parquet)")
        c.execute(f"COPY (SELECT * FROM raw.runs WHERE run_id='{a.run_id}') TO '{os.path.join(pq_dir, 'runs.parquet')}' (FORMAT parquet)")
        files["_parquet_dir"] = pq_dir.encode()
    except Exception as e:
        print(f"[varování] parquet export selhal: {type(e).__name__}: {e}", file=sys.stderr)
    man = [f"{sha256(files[n])}  {n}" for n in ("sidecar.prov.json", "results.jsonl", "summary.json")]
    for fn in sorted(os.listdir(pq_dir)):
        man.append(f"{sha256(open(os.path.join(pq_dir, fn), 'rb').read())}  parquet/{fn}")
    open(os.path.join(a.out, "MANIFEST.sha256"), "w").write("\n".join(man) + "\n")
    # snímek DB
    snap = os.path.join(os.path.dirname(os.path.abspath(a.db)), f"snapshot-{a.run_id}.sqlite")
    if not os.path.exists(snap): db.execute(f"VACUUM INTO '{snap}'")
    print(f"zapečetěno {a.run_id}: export → {a.out}, parquet → {pq_dir}, snímek → {snap}")
    for r in rows:
        if r[1] in ("all", "cf_proxied", "no_cf") and r[3] is not None and "share" in r[2]:
            print(f"  {r[1]:11} {r[2]:42} {r[3]:7.3f}  n={r[4]}")

# --- abort ------------------------------------------------------------------------------------------------
def cmd_abort(a):
    """Přerušený run: zapíše finished + poznámku ABORTED; data zůstávají, run se pak pečetí exportem jako ČÁSTEČNÝ (necituje se pro pásma)."""
    db = open_db(a.db)
    r = db.execute("SELECT finished, sealed_at FROM runs WHERE run_id=?", (a.run_id,)).fetchone()
    if not r: sys.exit("run neexistuje")
    if r[0] or r[1]: sys.exit("run už je finished/sealed — abort se netýká")
    n_done = db.execute("SELECT count(*) FROM domain_summary WHERE run_id=?", (a.run_id,)).fetchone()[0]
    n_partial = db.execute("SELECT count(DISTINCT domain) FROM fetch WHERE run_id=? AND domain NOT IN (SELECT domain FROM domain_summary WHERE run_id=?)", (a.run_id, a.run_id)).fetchone()[0]
    db.execute("UPDATE runs SET finished=?, notes=notes||? WHERE run_id=?", (now(), f" ABORTED: {a.reason}; complete={n_done} http_only={n_partial}", a.run_id)); db.commit()
    print(f"run {a.run_id} označen ABORTED (complete={n_done}, http_only={n_partial}); teď export → pečeť jako částečný")

# --- selftest -------------------------------------------------------------------------------------------
def cmd_selftest(a):
    """Pozitivní/negativní kontrola klasifikátoru a průchod žebříku na 4 kontrolních doménách (RFC §1)."""
    if os.path.exists(a.db): os.remove(a.db)
    pop = os.path.join(os.path.dirname(a.db), "selftest-pop.txt")
    open(pop, "w").write("cloudflare.com\nmedium.com\nseznam.cz\ntorumata.com\n")
    ns = argparse.Namespace(db=a.db, run_id="selftest", kind="selftest", population=pop, limit=0, seed=1, workers=4, chrome_workers=2,
                            delay=0.3, no_chrome=a.no_chrome, notes="selftest", allow_dirty=True, domain_slots=4, chrome_recycle=2, _no_exit=True)
    asyncio.run(cmd_run(ns))
    db = open_db(a.db)
    cls = dict(db.execute("SELECT domain, cf_class FROM domain_summary WHERE run_id='selftest'"))
    expect = {"cloudflare.com": "cf_proxied", "medium.com": "cf_proxied", "seznam.cz": "no_cf", "torumata.com": "no_cf"}
    ok = True
    for d, e in expect.items():
        flag = "ok" if cls.get(d) == e else "CHYBA"; ok &= cls.get(d) == e
        print(f"  {d:16} očekáváno {e:11} naměřeno {cls.get(d)!s:11} {flag}")
    rungs = db.execute("SELECT count(DISTINCT rung) FROM fetch WHERE run_id='selftest'").fetchone()[0]
    need = len(HTTP_RUNGS) + (0 if a.no_chrome else 2)
    print(f"  příčky zapsané: {rungs}/{need} {'ok' if rungs == need else 'CHYBA'}"); ok &= rungs == need
    db.execute("UPDATE runs SET sealed_at=? WHERE run_id='selftest'", (now(),)); db.commit()
    try:
        db.execute("DELETE FROM fetch WHERE run_id='selftest'"); print("  pečeť: CHYBA (DELETE prošel)"); ok = False
    except sqlite3.IntegrityError as e:
        print(f"  pečeť: ok ({e})")
    print("SELFTEST", "SPLNĚN" if ok else "SELHAL"); sys.exit(0 if ok else 2)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--run-id", required=True); r.add_argument("--kind", required=True)
    r.add_argument("--population", required=True); r.add_argument("--db", required=True); r.add_argument("--limit", type=int, default=0); r.add_argument("--holdout", help="soubor domen bez AI jmen (v6.3, Opus A7)")
    r.add_argument("--seed", type=int, default=20260914); r.add_argument("--workers", type=int, default=48); r.add_argument("--chrome-workers", type=int, default=16)
    r.add_argument("--delay", type=float, default=0.4); r.add_argument("--no-chrome", action="store_true"); r.add_argument("--notes", default="")
    r.add_argument("--allow-dirty", action="store_true")
    r.add_argument("--domain-slots", type=int, default=40, help="max rozpracovaných domén najednou (backpressure)")
    r.add_argument("--chrome-recycle", type=int, default=400, help="restart prohlížečů po N doménách")
    e = sub.add_parser("export"); e.add_argument("--run-id", required=True); e.add_argument("--db", required=True); e.add_argument("--out", required=True)
    s = sub.add_parser("selftest"); s.add_argument("--db", required=True); s.add_argument("--no-chrome", action="store_true")
    sub.add_parser("chromeworker"); sub.add_parser("robotstest")
    b = sub.add_parser("abort"); b.add_argument("--run-id", required=True); b.add_argument("--db", required=True); b.add_argument("--reason", required=True)
    a = ap.parse_args()
    {"run": lambda: asyncio.run(cmd_run(a)), "export": lambda: cmd_export(a), "selftest": lambda: cmd_selftest(a), "abort": lambda: cmd_abort(a),
     "chromeworker": chrome_worker_main, "robotstest": lambda: cmd_robotstest(a)}[a.cmd]()
