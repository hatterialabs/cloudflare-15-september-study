#!/usr/bin/env python3
"""cfstats — statistiky nad zapečetěným runem cfprobe (RFC §4b, vrstvy 1–4 z návrhu 2026-09-14).

  python3 scripts/cfstats.py report --db DB --run-id RUN [--out runs/RUN/report.md]
  python3 scripts/cfstats.py noise  --db DB --run-a RUN_A --run-b RUN_B [--out runs/RUN_B/noise-vs-RUN_A.md]

Vrstva 1 = kvalita měřidla · 2 = šumové dno (noise) · 3 = pre-registrované veličiny s Wilson 95% CI · 4 = popisná statistika
(pozorování s podmínkou, ne verdikt). Čísla se čtou jen ze zapečetěného runu (sealed_at IS NOT NULL) — jinak exit 2.
"""
import argparse, json, math, os, random, re, sqlite3, sys
from collections import Counter, defaultdict
import importlib.util
_spec = importlib.util.spec_from_file_location("cfprobe", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfprobe.py"))
cfprobe = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(cfprobe)
block_signature, PASS2_MIN_TEXT, TRAIN_BOTS_CLOSED = cfprobe.block_signature, cfprobe.PASS2_MIN_TEXT, cfprobe.TRAIN_BOTS
try:
    import zstandard
except ImportError:
    zstandard = None
QID = {1: "Q1 podíl cf_proxied", 2: "Q2 robots blokuje ≥1 z 9 tréninkových tokenů", 3: "Q3 Cloudflare managed marker M_B", 4: "Q4 neprůchod UA GPTBot / Googlebot, AI složka",
       5: "Q5 DiD markeru T0→T1 (ITT)", 6: "Q6 platný ads.txt", 7: "Q7 čitelnost pro lokálního agenta"}

RUNGS = ["L0", "L1", "L2", "L3", "L3r", "L4a", "L4b", "L4c", "L4g"]
RUNG_LABEL = {"L0": "skutečný Chrome", "L1": "headless Chrome", "L2": "HTTP knihovna, UA Chrome", "L3": "torumata-probe",
              "L3r": "python-requests", "L4a": "UA GPTBot", "L4b": "UA ClaudeBot", "L4c": "UA ChatGPT-User", "L4g": "UA Googlebot"}
TRAIN_BOTS = ["GPTBot", "ClaudeBot", "anthropic-ai", "CCBot", "Google-Extended", "Bytespider", "Applebot-Extended",
              "meta-externalagent", "Amazonbot"]
EXTRA = ["/llms.txt", "/llms-full.txt", "/ai.txt", "/sitemap.xml", "/.well-known/security.txt"]

def wilson(k, n, z=1.96):
    if not n: return (None, None, None)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))

def pct(t):
    p, lo, hi = t
    return "–" if p is None else f"{100*p:.1f} % [{100*lo:.1f}–{100*hi:.1f}]"

def chi2_2xk(table):
    """table: list of (k, n) per skupina → chi-kvadrát statistika a df (bez p-hodnoty knihovnou; p přes přežití chi2 aproximací)."""
    groups = [(k, n) for k, n in table if n]
    if len(groups) < 2: return None, None, None
    K = sum(k for k, _ in groups); N = sum(n for _, n in groups)
    if K == 0 or K == N: return 0.0, len(groups) - 1, 1.0
    p = K / N; chi = 0.0
    for k, n in groups:
        e1, e0 = n * p, n * (1 - p)
        chi += (k - e1) ** 2 / e1 + ((n - k) - e0) ** 2 / e0
    df = len(groups) - 1
    # p-hodnota: regularizovaná gama Q(df/2, chi/2) — numericky přes řadu / zlomek (bez scipy)
    return chi, df, gammaincc(df / 2, chi / 2)

def gammaincc(a, x):
    if x <= 0: return 1.0
    if x < a + 1:
        s = t = 1 / a; n = a
        for _ in range(500):
            n += 1; t *= x / n; s += t
            if abs(t) < abs(s) * 1e-12: break
        return 1 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
    b = x + 1 - a; c = 1e300; d = 1 / b; h = d
    for i in range(1, 500):
        an = -i * (i - a); b += 2; d = an * d + b; d = 1e-300 if d == 0 else d
        c = b + an / c; c = 1e-300 if c == 0 else c; d = 1 / d; de = d * c; h *= de
        if abs(de - 1) < 1e-12: break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h

class Run:
    def __init__(self, db, run_id):
        self.db, self.run_id = db, run_id
        r = db.execute("SELECT sealed_at, kind, started, finished, egress_ip, egress_org, script_commit, chrome_version, n_domains, n_errors FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not r: sys.exit(f"run {run_id} neexistuje")
        if not r[0]: sys.exit(f"run {run_id} není zapečetěný — statistiky se nečtou (exit 2)")
        self.meta = dict(zip(["sealed_at", "kind", "started", "finished", "egress_ip", "egress_org", "script_commit", "chrome_version", "n_domains", "n_errors"], r))
        self.dom = {}   # domain -> dict
        cols = lambda t: [c[1] for c in db.execute(f"PRAGMA table_info({t})")]
        has = {t: set(cols(t)) for t in ("domain_summary", "fetch", "robots", "ads")}
        extra_ds = ", reachable, cname_foreign" if "reachable" in has["domain_summary"] else ", NULL, NULL"
        for row in db.execute(f"SELECT domain, cc, stratum, cf_class, ns_cf, ip_cf, hdr_cf, resolver_mismatch, unreachable, llms_txt, jsonld, js_dep_ratio{extra_ds} FROM domain_summary WHERE run_id=?", (run_id,)):
            d = dict(zip(["domain", "cc", "stratum", "cf_class", "ns_cf", "ip_cf", "hdr_cf", "mismatch", "unreachable", "llms_mention", "jsonld", "js_dep", "reachable_v6", "cname_foreign"], row), fetch={}, robots=None, ads=None, extra={}, rank=None)
            for k in ("ns_cf", "ip_cf", "hdr_cf", "mismatch", "unreachable", "llms_mention", "jsonld"): d[k] = int(d[k] or 0)   # domény 'deadline' mají NULL
            self.dom[row[0]] = d
        for row in db.execute("SELECT domain, rank FROM population"):
            if row[0] in self.dom: self.dom[row[0]]["rank"] = row[1]
        extra_f = ", block_sig, body_sha, title, cf_mitigated, foreign_redirect" if "block_sig" in has["fetch"] else ", NULL, body_sha, title, cf_mitigated, NULL"
        for row in db.execute(f"SELECT domain, rung, status, pass, challenge, error, text_len, elapsed_ms, ts{extra_f} FROM fetch WHERE run_id=?", (run_id,)):
            if row[0] in self.dom: self.dom[row[0]]["fetch"][row[1]] = dict(zip(["status", "pass", "challenge", "error", "text_len", "elapsed_ms", "ts", "block_sig", "body_sha", "title", "cf_mitigated", "foreign_redirect"], row[2:]))
        extra_r = ", unobservable" if "unobservable" in has["robots"] else ", NULL"
        for row in db.execute(f"SELECT domain, status, is_text, cf_managed, content_signal, stances_json, star_blocked, ai_blocked_n, train_blocked, body_sha, via{extra_r} FROM robots WHERE run_id=?", (run_id,)):
            if row[0] in self.dom:
                d = dict(zip(["status", "is_text", "cf_managed", "content_signal", "stances", "star_blocked", "ai_blocked_n", "train_blocked", "sha", "via", "unobservable"], row[1:]))
                d["stances"] = json.loads(d["stances"] or "{}"); self.dom[row[0]]["robots"] = d
        # odvozené: dosažitelnost (Opus N2 / Gemini #1) a třída pro druhý jmenovatel
        for d in self.dom.values():
            skipped = any(v.get("error") == "skipped_unreachable" for v in d["fetch"].values())
            any_ok = any(v.get("error") is None and v.get("status") is not None for v in d["fetch"].values())
            d["reachable"] = int(bool(d["reachable_v6"]) if d["reachable_v6"] is not None else (not d["unreachable"] and not skipped and any_ok))
            d["cf_class2"] = d["cf_class"] if d["reachable"] else "unreachable"
        self._pass2_cache = {}
        reparse_robots(self)
        for row in db.execute("SELECT domain, status, valid_lines, html_ads FROM ads WHERE run_id=?", (run_id,)):
            if row[0] in self.dom: self.dom[row[0]]["ads"] = dict(zip(["status", "valid_lines", "html_ads"], row[1:]))
        for row in db.execute("SELECT domain, path, status, is_text, size FROM extra WHERE run_id=?", (run_id,)):
            if row[0] in self.dom: self.dom[row[0]]["extra"][row[1]] = dict(zip(["status", "is_text", "size"], row[2:]))
    def ccs(self): return sorted({d["cc"] for d in self.dom.values() if d["cc"]})
    def sel(self, cc=None, cls=None, stratum=None, l0=False, robots_ok=False, cls2=None, reachable=False):
        out = []
        for d in self.dom.values():
            if cc and d["cc"] != cc: continue
            if cls and d["cf_class"] != cls: continue
            if cls2 and d["cf_class2"] != cls2: continue
            if reachable and not d["reachable"]: continue
            if stratum == "top1000cz":
                if not (d["cc"] == "cz" and d["rank"] and d["rank"] <= 1000): continue   # strata CZ dle ranku (Opus N25)
            elif stratum == "restcz":
                if not (d["cc"] == "cz" and (d["rank"] or 10**9) > 1000): continue
            elif stratum and d["stratum"] != stratum: continue
            if l0 and not d["fetch"].get("L0", {}).get("pass"): continue
            if robots_ok and not (d["robots"] and d["robots"]["status"] == 200 and d["robots"]["is_text"]): continue
            out.append(d)
        return out

def boot_diff(xa, xb, n=1000, seed=20260915):
    """Bootstrap 95% CI rozdílu podílů (A − B) přes domény."""
    if not xa or not xb: return (None, None)
    rng = random.Random(seed); na, nb = len(xa), len(xb); diffs = []
    for _ in range(n):
        sa = sum(xa[rng.randrange(na)] for _ in range(na)) / na; sb = sum(xb[rng.randrange(nb)] for _ in range(nb)) / nb; diffs.append(sa - sb)
    diffs.sort(); return (diffs[int(0.025 * n)], diffs[int(0.975 * n) - 1])

def share(items, pred):
    n = len(items); k = sum(1 for d in items if pred(d)); return wilson(k, n), k, n

def parse_robots_v5(txt):
    """Doslovná kopie parseru z T0 (cfprobe commit 8ad033a): více UA řádků za sebou → pravidla jen poslednímu (chyba vůči RFC 9309), citlivé na velikost jen u tokenů? ne — tokeny lower()."""
    groups, cur = {}, []
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line: continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "user-agent":
            cur = [v.lower()]; groups.setdefault(v.lower(), [])
        elif k in ("disallow", "allow", "content-signal"):
            for u in (cur or ["*"]): groups.setdefault(u, []).append((k, v))
    return groups
def stance_v5(groups, bot):
    g = groups.get(bot.lower())
    if g is None: return "unaddressed"
    dis = [p for d, p in g if d == "disallow"]
    if "/" in dis: return "blocked"
    if dis: return "partial"
    return "allowed"

def reparse_robots(run):
    """Obě čtení parseru z uložených robots.txt (Opus N8): 'old' = parser T0 (pre-registrace), 'new' = RFC 9309 (v6). Plní d['robots']['tb_old'|'tb_new'|'mb_old'|'mb_new']."""
    if not _dctx: return
    dctx = _dctx
    for d in run.dom.values():
        r = d["robots"]
        if not r or r["status"] != 200 or not r["is_text"] or not r.get("sha"): continue
        row = run.db.execute("SELECT bytes_zstd FROM blobs WHERE sha256=?", (r["sha"],)).fetchone()
        if not row: continue
        txt = dctx.decompress(row[0], max_output_size=5_000_000).decode(errors="replace")
        g5, g6 = parse_robots_v5(txt), cfprobe.parse_robots(txt)
        r["tb_old"] = int(any(stance_v5(g5, b) == "blocked" for b in TRAIN_BOTS_CLOSED))
        r["tb_new"] = int(any(cfprobe.stance(g6, b) == "blocked" for b in TRAIN_BOTS_CLOSED))
        r["mb_old"] = int("BEGIN Cloudflare Managed content" in txt)
        r["mb_new"] = int("begin cloudflare managed content" in txt.lower())
        r["bps"] = int("bot preference sync" in txt.lower())   # 18. 9.: nový marker Cloudflare (Bot Preference Sync), nahrazuje managed robots.txt
        tl = txt.lower(); i0 = tl.find("begin cloudflare"); i1 = tl.find("end cloudflare")   # blok Cloudflare (managed i BPS)
        cs = [m.start() for m in re.finditer(r"^\s*content-signal\s*:", tl, flags=re.M)]
        r["mc_in_block"] = int(any(i0 != -1 and i0 <= p <= (i1 if i1 != -1 else len(tl)) for p in cs))   # Opus 18. 9.: M_C uvnitř bloku Cloudflare
        r["mc_out_block"] = int(any(not (i0 != -1 and i0 <= p <= (i1 if i1 != -1 else len(tl))) for p in cs))

def rung_pass(d, r): return bool(d["fetch"].get(r, {}).get("pass"))

_dctx = zstandard.ZstdDecompressor() if zstandard else None
def blob_text(db, sha, cap=300_000):
    if not sha or not _dctx: return None
    row = db.execute("SELECT bytes_zstd FROM blobs WHERE sha256=?", (sha,)).fetchone()
    if not row: return None
    raw = _dctx.decompress(row[0], max_output_size=8_000_000)[:cap].decode(errors="replace")
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)))

def rung_pass2(run, d, r):
    """pass2 = pass ∧ žádná signatura blokové stránky (titulek + tělo, je-li v skladu) ∧ text ≥ PASS2_MIN_TEXT (L0: innerText; HTTP: text z blobu, je-li)."""
    key = (d["domain"], r)
    if key in run._pass2_cache: return run._pass2_cache[key]
    f = d["fetch"].get(r)
    ok = False
    if f and f.get("pass"):
        sig = f.get("block_sig") or block_signature(f.get("title") or "", "")
        if sig is None:
            if r in ("L0", "L1"): ok = (f.get("text_len") or 0) >= PASS2_MIN_TEXT
            else:
                txt = blob_text(run.db, f.get("body_sha"))
                if txt is None: ok = True                          # bez těla (T0 L4*) = jen titulek/status
                else: ok = block_signature("", txt[:8000]) is None and len(txt.strip()) >= PASS2_MIN_TEXT
    run._pass2_cache[key] = ok
    return ok

def fail_cause(d, r):
    f = d["fetch"].get(r)
    if not f: return "chybí"
    if f.get("pass"): return "pass"
    if f.get("error") == "skipped_unreachable": return "nedostupné"
    if f.get("error"): return "timeout/spojení"
    if f.get("challenge"): return "challenge"
    st = f.get("status") or 0
    if st == 403: return "403"
    if st == 429: return "429"
    if st >= 500: return "5xx"
    if st >= 400: return "jiné 4xx"
    return "jiné"
def rung_present(d, r): return r in d["fetch"] and d["fetch"][r].get("error") != "skipped_unreachable"

def block_type(d):
    """Typologie blokace z žebříku (jen pro L0 pass)."""
    f = lambda r: rung_pass(d, r)
    if not f("L0"): return "člověk neprojde"
    if not f("L1"): return "blokuje i headless prohlížeč"
    if not f("L2") and not f("L3") and not f("L3r"): return "blokuje vše mimo prohlížeč"
    if f("L3") and not f("L3r"): return "UA blocklist (python-requests padá, neutrální UA prochází)"
    if f("L3") and f("L3r") and not (f("L4a") and f("L4b") and f("L4c")): return "blokuje jen jmenované AI boty"
    if f("L2") and f("L3") and f("L3r") and f("L4a") and f("L4b") and f("L4c"): return "otevřený"
    return "smíšený"

def report(run, out):
    L = []; w = L.append
    m = run.meta; ccs = run.ccs(); all_d = list(run.dom.values())
    w(f"# Report runu `{run.run_id}` (kind {m['kind']})\n")
    w(f"autor-křeslo: exekutor (generováno `scripts/cfstats.py`) · zapečetěno {m['sealed_at']} · skript {m['script_commit'][:10] if m['script_commit'] else '?'} · Chrome {m['chrome_version']} · egress {m['egress_ip']} ({m['egress_org']}) · start {m['started']} · konec {m['finished']} · domén {m['n_domains']} · chyb {m['n_errors']}\n")
    w("> Status: **pozorování**. Verdikty (TREFA/MIMO) nad pásmy píše držitel běhu zvlášť; vrstva 4 je materiál, ne závěr.\n")

    # ---------- vrstva 1: kvalita měřidla
    w("## 1. Kvalita měřidla\n")
    w("| země | domén | unresolved | skipped_unreachable | L0 pass | L0 chyba | L0 challenge | DNS neshoda resolverů | CF: IP≠hlavička |")
    w("|---|---|---|---|---|---|---|---|---|")
    def qrow(label, items):
        n = len(items)
        unres = sum(d["unreachable"] for d in items)
        skip = sum(1 for d in items if any(v.get("error") == "skipped_unreachable" for v in d["fetch"].values()))
        l0p = sum(1 for d in items if rung_pass(d, "L0")); l0e = sum(1 for d in items if d["fetch"].get("L0", {}).get("error") not in (None, "skipped_unreachable"))
        l0c = sum(1 for d in items if d["fetch"].get("L0", {}).get("challenge"))
        mm = sum(d["mismatch"] for d in items)
        cfm = sum(1 for d in items if (bool(d["ip_cf"]) != bool(d["hdr_cf"])) and not d["unreachable"] and rung_present(d, "L2") and not d["fetch"]["L2"].get("error"))
        w(f"| {label} | {n} | {unres} ({100*unres/n:.1f} %) | {skip} ({100*skip/n:.1f} %) | {l0p} ({100*l0p/n:.1f} %) | {l0e} | {l0c} | {mm} | {cfm} |")
    qrow("**vše**", all_d)
    for cc in ccs: qrow(cc, run.sel(cc=cc))
    w("\nChyby per příčka (bez skipped):\n")
    errs = Counter(); tot = Counter()
    for d in all_d:
        for r, v in d["fetch"].items():
            if v.get("error") == "skipped_unreachable": continue
            tot[r] += 1
            if v.get("error"): errs[(r, v["error"])] += 1
    w("| příčka | pokusů | chyby |"); w("|---|---|---|")
    for r in RUNGS:
        e = ", ".join(f"{k[1]} {v}" for k, v in sorted(errs.items(), key=lambda x: -x[1]) if k[0] == r)
        w(f"| {r} {RUNG_LABEL[r]} | {tot[r]} | {e or '—'} |")
    # pořadí zpracování vs blokace (permutační kontrola reputace IP)
    ts = sorted(((d["fetch"]["L2"]["ts"], d["domain"], d) for d in all_d if d["fetch"].get("L2", {}).get("ts") and rung_pass(d, "L0")), key=lambda x: (x[0], x[1]))
    if len(ts) >= 200:
        q = len(ts) // 4
        w("\nBlokace L2 (knihovna s UA Chrome) podle pořadí v běhu (čtvrtiny; růst ke konci = reputace naší IP, ne politika webů):\n")
        w("| čtvrtina běhu | domén (L0 pass) | L2 fail |"); w("|---|---|---|")
        for i in range(4):
            part = [d for _, _, d in ts[i*q:(i+1)*q if i < 3 else len(ts)]]
            t, k, n = share(part, lambda d: not rung_pass(d, "L2")); w(f"| {i+1}. | {n} | {pct(t)} |")

    # dosažitelnost (Opus N2)
    w("\n**Dosažitelnost (Opus N2 / Gemini #1):** " + " · ".join(f"{k}: {v}" for k, v in Counter(d["cf_class2"] for d in all_d).most_common()) + f" · reachable celkem {sum(d['reachable'] for d in all_d)}/{len(all_d)}\n")
    # konzistence markeru (Opus N9): M_B ⇒ 8 tokenů blocked
    mb = [d for d in run.sel(robots_ok=True) if d["robots"]["cf_managed"]]
    mb_ok = sum(1 for d in mb if sum(1 for b in ("Amazonbot", "Applebot-Extended", "Bytespider", "CCBot", "ClaudeBot", "Google-Extended", "GPTBot", "meta-externalagent") if d["robots"]["stances"].get(b) == "blocked") >= 8)
    w(f"**Konzistence markeru M_B (Opus N9):** M_B přítomen u {len(mb)} domén; z toho s ≥8 blokovanými tokeny {mb_ok} ({(100*mb_ok/len(mb)) if mb else 0:.1f} %); zbytek = forenzika (přepis originem nebo chyba parseru).\n")
    # permutační kontrola: fail podle pořadí příčky v doméně (Opus N20)
    pos_fail = defaultdict(lambda: [0, 0])
    for d in all_d:
        seq = sorted(((v["ts"], r) for r, v in d["fetch"].items() if r not in ("L0", "L1") and v.get("ts") and v.get("error") != "skipped_unreachable"), key=lambda x: x[0])
        if len(seq) < 7: continue   # jen domény se všemi HTTP příčkami (přeskočené po 2 selháních by zkreslily první pozice)
        for i, (_, r) in enumerate(seq):
            pos_fail[i + 1][1] += 1; pos_fail[i + 1][0] += 0 if rung_pass(d, r) else 1
    w("\nNeprůchod HTTP příčky podle pořadí v doméně (pořadí je náhodné per doména; růst s pořadím = rate-limit hrany, ne politika):\n")
    w("| pořadí | n | ¬pass |"); w("|---|---|---|")
    for i in sorted(pos_fail):
        k, n = pos_fail[i]; w(f"| {i}. | {n} | {pct(wilson(k, n))} |")
    # rozpad ¬pass (Opus N14)
    w("\nRozpad neprůchodu per příčka a rameno (jmenovatel L0 pass):\n")
    w("| rameno | příčka | pass | 403 | 429 | challenge | 5xx | jiné 4xx | timeout/spojení | jiné |"); w("|---|---|---|---|---|---|---|---|---|---|")
    for cls in ("cf_proxied", "no_cf"):
        items = run.sel(cls=cls, l0=True)
        for r in ("L2", "L3", "L3r", "L4a", "L4g"):
            c = Counter(fail_cause(d, r) for d in items); n = len(items) or 1
            w(f"| {cls} | {r} | " + " | ".join(f"{100*c[k]/n:.1f} %" for k in ("pass", "403", "429", "challenge", "5xx", "jiné 4xx", "timeout/spojení", "jiné")) + " |")

    # ---------- vrstva 3: pre-registrované veličiny
    w("\n## 3. Pre-registrované veličiny (Wilson 95% CI) — skóruje se proti `bands/cf-T0/`\n")
    w("> Pravidlo skórování (RFC dodatek, Opus reakce §0.3): pásma commitnutá před T0 se skórují výhradně čteními označenými PRE-REGISTROVANÉ (definice z obálky + `cfstats.py` de597d2). Čtení označená 'definováno po expozici T0' (pass2, AI trojice, M_B zvlášť, reachable, cf_class2) jsou citlivost, ne verdikt.\n")
    def scope_rows(title, fn, scopes):
        w(f"\n**{title}**\n"); w("| scope | hodnota | k/n |"); w("|---|---|---|")
        for label, items in scopes:
            t, k, n = fn(items); w(f"| {label} | {pct(t)} | {k}/{n} |")
    def scopes_basic(cls=None, l0=False, robots_ok=False):
        s = [("vše", run.sel(cls=cls, l0=l0, robots_ok=robots_ok))]
        for cc in ccs:
            s.append((cc, run.sel(cc=cc, cls=cls, l0=l0, robots_ok=robots_ok)))
            strata = ("top1000cz", "restcz") if cc == "cz" else ("top1000", "random1000")
            for st in strata:
                items = run.sel(cc=cc, cls=cls, stratum=st, l0=l0, robots_ok=robots_ok)
                if items: s.append((f"{cc} · {st}", items))
        return s
    scope_rows(f"{QID[1]} — jmenovatel: všechny domény vč. unresolved (pre-registrace)", lambda it: share(it, lambda d: d["cf_class"] == "cf_proxied"), scopes_basic())
    scope_rows(f"{QID[1]} — jmenovatel: dosažitelné domény (Opus N2, citlivost)", lambda it: share([d for d in it if d["reachable"]], lambda d: d["cf_class"] == "cf_proxied"), scopes_basic())
    scope_rows("Q1b. podíl `cf_dns_only` / `unreachable` (vše)", lambda it: share(it, lambda d: d["cf_class2"] == "cf_dns_only"), [("vše", all_d)] + [(cc, run.sel(cc=cc)) for cc in ccs])
    scope_rows(f"{QID[2]} (jmenovatel: robots 200 text; tokeny uzavřené: {', '.join(TRAIN_BOTS_CLOSED)})", lambda it: share(it, lambda d: d["robots"]["train_blocked"]), scopes_basic(robots_ok=True))
    scope_rows("Q2 — PRE-REGISTROVANÉ ČTENÍ (parser T0, přepočet z blobů)", lambda it: share(it, lambda d: bool(d["robots"].get("tb_old", d["robots"]["train_blocked"]))), scopes_basic(robots_ok=True))
    scope_rows("Q2 — parser RFC 9309 (v6; definováno po expozici T0)", lambda it: share(it, lambda d: bool(d["robots"].get("tb_new", d["robots"]["train_blocked"]))), scopes_basic(robots_ok=True))
    nd = sum(1 for d in run.sel(robots_ok=True) if d["robots"].get("tb_old") is not None and d["robots"]["tb_old"] != d["robots"]["tb_new"])
    w(f"\nNeshoda parserů (starý vs RFC 9309) u train_blocked: {nd} domén z {len(run.sel(robots_ok=True))} s robots 200 text (Opus N8; starý parser přiřazoval pravidla jen poslednímu z více UA řádků → podhodnocoval blokace).\n")
    scope_rows("Q2b. `User-agent: *` s `Disallow: /` (dědění, hlášeno zvlášť)", lambda it: share(it, lambda d: d["robots"]["star_blocked"]), scopes_basic(robots_ok=True))
    scope_rows(f"{QID[3]} — PRE-REGISTROVANÉ ČTENÍ (obálka bod 3): M_B ∨ M_C mezi VŠEMI `cf_proxied` (robots ≠ 200 ⇒ M = 0; Opus reakce §2.4a)", lambda it: share(it, lambda d: bool(d["robots"] and d["robots"]["status"] == 200 and d["robots"]["is_text"] and (d["robots"]["cf_managed"] or d["robots"]["content_signal"]))), scopes_basic(cls="cf_proxied"))
    scope_rows(f"{QID[3]} — M_B `BEGIN Cloudflare Managed content` mezi `cf_proxied` (robots 200 text) [čtení pro článek; definováno po expozici T0]", lambda it: share(it, lambda d: bool(d["robots"]["cf_managed"])), scopes_basic(cls="cf_proxied", robots_ok=True))
    scope_rows("Q3b. M_C `Content-signal:` mezi `cf_proxied` (zvlášť, Opus N9)", lambda it: share(it, lambda d: bool(d["robots"]["content_signal"])), scopes_basic(cls="cf_proxied", robots_ok=True))
    scope_rows("Q3c. M_B ∨ M_C (pre-registrované čtení z obálky)", lambda it: share(it, lambda d: d["robots"]["cf_managed"] or bool(d["robots"]["content_signal"])), scopes_basic(cls="cf_proxied", robots_ok=True))
    scope_rows("Q3d. M_C mezi `no_cf` (placebo: syntaxe bez Cloudflare)", lambda it: share(it, lambda d: bool(d["robots"]["content_signal"])), scopes_basic(cls="no_cf", robots_ok=True))
    scope_rows("Q3 kotva (Opus N23): podíl `cf_proxied` s ≥8 z 8 managed tokenů blocked (strop M_B)", lambda it: share(it, lambda d: sum(1 for b in ("Amazonbot", "Applebot-Extended", "Bytespider", "CCBot", "ClaudeBot", "Google-Extended", "GPTBot", "meta-externalagent") if d["robots"]["stances"].get(b) == "blocked") >= 8), scopes_basic(cls="cf_proxied", robots_ok=True))
    for cls in ("cf_proxied", "no_cf"):
        scope_rows(f"4. L4 (UA GPTBot) neprojde mezi L0 pass · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L4a")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"4b. L4' (UA Googlebot) neprojde mezi L0 pass · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L4g")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"4c. AI-specifická složka (L4 fail ∧ L3 pass) · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L4a") and rung_pass(d, "L3")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"4d. L4 fail ∧ L4' pass (GPTBot blokován, Googlebot UA ne) · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L4a") and rung_pass(d, "L4g")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"4e. AI := ¬L4 ∧ L3 ∧ L4' (Opus N13, primární od T1) · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L4a") and rung_pass(d, "L3") and rung_pass(d, "L4g")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"4f. L4 ¬pass2 (zpřísněné čtení, Opus N11) · {cls}", lambda it: share(it, lambda d: not rung_pass2(run, d, "L4a")), scopes_basic(cls=cls, l0=True))
    scope_rows(f"{QID[6]} mezi `cf_proxied` (L0 pass)", lambda it: share(it, lambda d: bool(d["ads"] and d["ads"]["valid_lines"] > 0)), scopes_basic(cls="cf_proxied", l0=True))
    scope_rows("Q6 srovnání: platný ads.txt mezi `no_cf` (L0 pass)", lambda it: share(it, lambda d: bool(d["ads"] and d["ads"]["valid_lines"] > 0)), scopes_basic(cls="no_cf", l0=True))
    scope_rows("6b. HTML signatura reklamy mezi `cf_proxied` (L0 pass)", lambda it: share(it, lambda d: bool(d["ads"] and d["ads"]["html_ads"])), scopes_basic(cls="cf_proxied", l0=True))
    for cls in ("cf_proxied", "no_cf"):
        scope_rows(f"7a. L3 pass (poctivá knihovna projde) · {cls}", lambda it: share(it, lambda d: rung_pass(d, "L3")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"7b. L0 pass ∧ L2 fail (prohlížeč řízený programem ano, knihovna s UA Chrome ne) · {cls}", lambda it: share(it, lambda d: not rung_pass(d, "L2")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"7c. L3 ¬pass2 (zpřísněné, Opus N11) · {cls}", lambda it: share(it, lambda d: not rung_pass2(run, d, "L3")), scopes_basic(cls=cls, l0=True))
        scope_rows(f"7d. L2 ¬pass2 (zpřísněné, Opus N11) · {cls}", lambda it: share(it, lambda d: not rung_pass2(run, d, "L2")), scopes_basic(cls=cls, l0=True))
    # rozdíl cf_proxied − no_cf
    w("\n**Rozdíl cf_proxied − no_cf (p.b.), jmenovatel L0 pass, vše; 95% bootstrap přes domény (Opus N24):**\n"); w("| veličina | cf_proxied | no_cf | rozdíl [95% CI] |"); w("|---|---|---|---|")
    A, B = run.sel(cls="cf_proxied", l0=True), run.sel(cls="no_cf", l0=True)
    for lab, pred in [("L4 fail", lambda d: not rung_pass(d, "L4a")), ("L4' fail", lambda d: not rung_pass(d, "L4g")), ("L3 fail", lambda d: not rung_pass(d, "L3")),
                      ("L3r fail", lambda d: not rung_pass(d, "L3r")), ("L2 fail", lambda d: not rung_pass(d, "L2")), ("L1 fail", lambda d: not rung_pass(d, "L1")),
                      ("AI := ¬L4 ∧ L3 ∧ L4'", lambda d: not rung_pass(d, "L4a") and rung_pass(d, "L3") and rung_pass(d, "L4g")),
                      ("L3 ¬pass2", lambda d: not rung_pass2(run, d, "L3")), ("robots blokuje trénink (jmen. robots ok)", None), ("ads.txt platný", lambda d: bool(d["ads"] and d["ads"]["valid_lines"] > 0))]:
        if pred is None:
            A2, B2 = run.sel(cls="cf_proxied", robots_ok=True), run.sel(cls="no_cf", robots_ok=True); pred = lambda d: bool(d["robots"]["train_blocked"]); a, b = share(A2, pred), share(B2, pred); xa, xb = [int(pred(d)) for d in A2], [int(pred(d)) for d in B2]
        else:
            a, b = share(A, pred), share(B, pred); xa, xb = [int(pred(d)) for d in A], [int(pred(d)) for d in B]
        lo, hi = boot_diff(xa, xb)
        diff = (100 * (a[0][0] - b[0][0])) if a[0][0] is not None and b[0][0] is not None else None
        w(f"| {lab} | {pct(a[0])} | {pct(b[0])} | {'–' if diff is None else f'{diff:+.1f} [{100*lo:+.1f}, {100*hi:+.1f}]'} |")

    # ---------- vrstva 4: popisná statistika
    w("\n## 4. Popisná statistika (pozorování s podmínkou; před publikací pre-registrovat)\n")
    # 4.1 CF třídy per země a stratum
    w("### 4.1 Třídy Cloudflare per země a stratum\n")
    w("| země | stratum | n | cf_proxied | cf_dns_only | no_cf | unresolved |"); w("|---|---|---|---|---|---|---|")
    for cc in ccs:
        for st in (None, "top1000", "random1000"):
            items = run.sel(cc=cc, stratum=st)
            if not items: continue
            c = Counter(d["cf_class"] for d in items); n = len(items)
            w(f"| {cc} | {st or 'vše'} | {n} | {100*c['cf_proxied']/n:.1f} % | {100*c['cf_dns_only']/n:.1f} % | {100*c['no_cf']/n:.1f} % | {100*c['unresolved']/n:.1f} % |")
    tab = [(sum(1 for d in run.sel(cc=cc) if d["cf_class"] == "cf_proxied"), len(run.sel(cc=cc))) for cc in ccs]
    chi, df, p = chi2_2xk(tab)
    if chi is not None: w(f"\nChí-kvadrát homogenity podílu cf_proxied napříč zeměmi: χ²={chi:.1f}, df={df}, p={p:.2e}\n")
    # 4.2 robots
    w("### 4.2 robots.txt\n")
    rok = run.sel(robots_ok=True)
    w(f"- robots.txt 200 a textový: {len(rok)}/{len(all_d)} domén ({100*len(rok)/len(all_d):.1f} %); `User-agent: *` s `Disallow: /`: {sum(1 for d in rok if d['robots']['star_blocked'])}")
    named = Counter(); blocked = Counter()
    for d in rok:
        for bot, st in d["robots"]["stances"].items():
            if st != "unaddressed": named[bot] += 1
            if st == "blocked": blocked[bot] += 1
    w("\n| bot | jmenován v robots.txt | z toho `Disallow: /` | blokován (% z robots ok) |"); w("|---|---|---|---|")
    for bot, k in named.most_common():
        w(f"| {bot} | {k} | {blocked[bot]} | {100*blocked[bot]/len(rok):.1f} % |")
    w(f"\n- `Content-signal:` přítomen: {sum(1 for d in rok if d['robots']['content_signal'])} · Cloudflare managed blok: {sum(1 for d in rok if d['robots']['cf_managed'])}")
    w("\n| země | robots ok | blokuje ≥1 AI bota | blokuje ≥1 tréninkového | Content-signal | CF managed |"); w("|---|---|---|---|---|---|")
    for cc in ccs:
        it = run.sel(cc=cc, robots_ok=True); n = len(it)
        if not n: continue
        w(f"| {cc} | {n} | {100*sum(1 for d in it if d['robots']['ai_blocked_n']>0)/n:.1f} % | {100*sum(1 for d in it if d['robots']['train_blocked'])/n:.1f} % | {sum(1 for d in it if d['robots']['content_signal'])} | {sum(1 for d in it if d['robots']['cf_managed'])} |")
    # 4.3 politika vs vynucení
    w("\n### 4.3 Mezera politika (robots.txt) vs vynucení (hrana), jmenovatel: L0 pass ∧ robots ok\n")
    w("| země | n | robots zakazuje GPTBot ∧ hrana UA GPTBot pustí | robots mlčí ∧ hrana UA GPTBot blokuje | robots zakazuje ∧ hrana blokuje | robots mlčí ∧ hrana pustí |"); w("|---|---|---|---|---|---|")
    def gap_row(label, it):
        n = len(it)
        if not n: return
        a = sum(1 for d in it if d["robots"]["stances"].get("GPTBot") == "blocked" and rung_pass(d, "L4a"))
        b = sum(1 for d in it if d["robots"]["stances"].get("GPTBot") != "blocked" and not rung_pass(d, "L4a"))
        c = sum(1 for d in it if d["robots"]["stances"].get("GPTBot") == "blocked" and not rung_pass(d, "L4a"))
        e = sum(1 for d in it if d["robots"]["stances"].get("GPTBot") != "blocked" and rung_pass(d, "L4a"))
        w(f"| {label} | {n} | {a} ({100*a/n:.1f} %) | {b} ({100*b/n:.1f} %) | {c} ({100*c/n:.1f} %) | {e} ({100*e/n:.1f} %) |")
    gap_row("vše", run.sel(l0=True, robots_ok=True))
    for cls in ("cf_proxied", "no_cf"): gap_row(cls, run.sel(cls=cls, l0=True, robots_ok=True))
    for cc in ccs: gap_row(cc, run.sel(cc=cc, l0=True, robots_ok=True))
    # 4.4 typologie
    w("\n### 4.4 Typologie blokace z žebříku (jmenovatel: L0 pass)\n")
    w("| typ | vše | cf_proxied | no_cf |"); w("|---|---|---|---|")
    ty = {k: Counter(block_type(d) for d in run.sel(cls=None if k == "vše" else k, l0=True)) for k in ("vše", "cf_proxied", "no_cf")}
    ns = {k: len(run.sel(cls=None if k == "vše" else k, l0=True)) for k in ty}
    for t in sorted(set().union(*[c.keys() for c in ty.values()]), key=lambda t: -ty["vše"][t]):
        w(f"| {t} | " + " | ".join(f"{100*ty[k][t]/ns[k]:.1f} % ({ty[k][t]})" if ns[k] else "–" for k in ty) + " |")
    w("\nPass matice per příčka (jmenovatel L0 pass):\n")
    w("| scope | " + " | ".join(RUNGS[1:]) + " |"); w("|---|" + "---|" * len(RUNGS[1:]))
    for label, it in [("vše", run.sel(l0=True)), ("cf_proxied", run.sel(cls="cf_proxied", l0=True)), ("no_cf", run.sel(cls="no_cf", l0=True))] + [(cc, run.sel(cc=cc, l0=True)) for cc in ccs]:
        if not it: continue
        w(f"| {label} (n={len(it)}) | " + " | ".join(f"{100*sum(1 for d in it if rung_pass(d, r))/len(it):.1f} %" for r in RUNGS[1:]) + " |")
    # 4.5 soubory a strukturovaná data
    w("\n### 4.5 Soubory pro AI a strukturovaná data per země (jmenovatel: dosažitelné domény)\n")
    w("| země | n | llms.txt | llms-full.txt | ai.txt | sitemap.xml | security.txt | ads.txt | JSON-LD | JS-závislost: text bez JS < 20 % |"); w("|---|---|---|---|---|---|---|---|---|---|")
    def files_row(label, it):
        it = [d for d in it if not d["unreachable"]]; n = len(it)
        if not n: return
        ex = lambda p: sum(1 for d in it if d["extra"].get(p, {}).get("status") == 200 and d["extra"][p].get("is_text"))
        ads = sum(1 for d in it if d["ads"] and d["ads"]["valid_lines"] > 0); jl = sum(d["jsonld"] for d in it)
        jsd = [d for d in it if d["js_dep"] is not None]; heavy = sum(1 for d in jsd if d["js_dep"] > 5)
        w(f"| {label} | {n} | {100*ex('/llms.txt')/n:.1f} % | {100*ex('/llms-full.txt')/n:.1f} % | {100*ex('/ai.txt')/n:.1f} % | {100*ex('/sitemap.xml')/n:.1f} % | {100*ex('/.well-known/security.txt')/n:.1f} % | {100*ads/n:.1f} % | {100*jl/n:.1f} % | {(f'{100*heavy/len(jsd):.1f} % (n={len(jsd)})' if jsd else '–')} |")
    files_row("vše", all_d)
    for cc in ccs: files_row(cc, run.sel(cc=cc))
    w("\nPozn.: JS-závislost = text po renderu (L0) / text bez JS (L2); >5 = bez JavaScriptu je vidět méně než 20 % obsahu. Počítá se jen kde L0 i L2 prošly.\n")
    # 4.6 hlava vs tělo
    w("### 4.6 Hlava (top1000) vs tělo (random1000) uvnitř země — reprezentuje top web zbytek?\n")
    w("| země | veličina | top1000 | random1000 | χ² p |"); w("|---|---|---|---|---|")
    for cc in ccs:
        for lab, pred, kw in [("cf_proxied", lambda d: d["cf_class"] == "cf_proxied", {}), ("blokuje tréninkového bota", lambda d: d["robots"]["train_blocked"], {"robots_ok": True}),
                              ("L2 fail (L0 pass)", lambda d: not rung_pass(d, "L2"), {"l0": True}), ("llms.txt", lambda d: d["extra"].get("/llms.txt", {}).get("status") == 200 and d["extra"]["/llms.txt"].get("is_text"), {})]:
            a = run.sel(cc=cc, stratum="top1000", **kw); b = run.sel(cc=cc, stratum="random1000", **kw)
            if not a or not b: continue
            sa, sb = share(a, pred), share(b, pred); chi, df, p = chi2_2xk([(sa[1], sa[2]), (sb[1], sb[2])])
            w(f"| {cc} | {lab} | {pct(sa[0])} | {pct(sb[0])} | {p:.3f} |")
    text = "\n".join(L) + "\n"
    if out:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True); open(out, "w").write(text); print(f"report → {out} ({len(L)} řádků)")
    else:
        print(text)

def noise(db, a, b, out):
    ra, rb = Run(db, a), Run(db, b)
    common = sorted(set(ra.dom) & set(rb.dom)); L = []; w = L.append
    w(f"# Šumové dno: `{a}` vs `{b}`\n"); w(f"společných domén: {len(common)} · A start {ra.meta['started']} · B start {rb.meta['started']}\n")
    w("| veličina | domén se změnou | z n | podíl |"); w("|---|---|---|---|")
    def row(lab, pred, pool=None):
        pool = pool or common; k = sum(1 for d in pool if pred(ra.dom[d], rb.dom[d])); n = len(pool); w(f"| {lab} | {k} | {n} | {pct(wilson(k, n))} |")
    row("CF třída", lambda x, y: x["cf_class"] != y["cf_class"])
    row("robots.txt hash", lambda x, y: (x["robots"] or {}).get("sha") != (y["robots"] or {}).get("sha"), [d for d in common if ra.dom[d]["robots"] and rb.dom[d]["robots"] and ra.dom[d]["robots"]["status"] == 200 and rb.dom[d]["robots"]["status"] == 200])
    row("robots: blokuje tréninkového bota", lambda x, y: bool((x["robots"] or {}).get("train_blocked")) != bool((y["robots"] or {}).get("train_blocked")))
    row("robots: CF managed / Content-signal", lambda x, y: bool((x["robots"] or {}).get("cf_managed") or (x["robots"] or {}).get("content_signal")) != bool((y["robots"] or {}).get("cf_managed") or (y["robots"] or {}).get("content_signal")))
    for r in RUNGS:
        row(f"{r} pass/fail", lambda x, y, r=r: rung_pass(x, r) != rung_pass(y, r), [d for d in common if rung_present(ra.dom[d], r) and rung_present(rb.dom[d], r)])
    row("ads.txt platný", lambda x, y: bool(x["ads"] and x["ads"]["valid_lines"] > 0) != bool(y["ads"] and y["ads"]["valid_lines"] > 0))
    w("\nČtení: delta T0→T1 u veličiny je informativní jen nad tímto podílem změn (a nad rozdílem cf_proxied − no_cf).\n")
    text = "\n".join(L) + "\n"
    if out: os.makedirs(os.path.dirname(out) or ".", exist_ok=True); open(out, "w").write(text); print(f"noise → {out}")
    else: print(text)

def delta(db, a, b, noise_b, out, c=3.0, noise_a=None):
    """Q5: DiD markeru M_B mezi run A (baseline T0a) a run B (T1), třída ITT z A, M=0 při robots≠200; šumové dno = DiD(A→noise_b).
    Pravidlo (redakční, c schvaluje uživatel): skok ⇔ dolní mez 95% bootstrap CI > 0 ∧ DiD > c·|šum|. Vedle: podmíněná delta (stejný finální host + třída, Gemini #4)."""
    ra, rb = Run(db, a), Run(db, b); rn = Run(db, noise_b) if noise_b else None
    rna = Run(db, noise_a) if (noise_a and noise_a != a) else ra   # oprava 22. 9. (Opus T2 A1): šumové dno = obrat mezi dvojicí téhož dne (noise_a, noise_b), nezávisle na A
    def M(run, dom, mode="prereg"):
        """M dle obálky = M_B ∨ M_C, jen z cesty v5 (robots via L3/L2); mode='v6' zahrne i Chrome fallback (citlivost, Opus 2.1);
        mode='MB' = jen M_B (čtení pro článek). robots ≠ 200 ⇒ M = 0 (obálka bod 3/5)."""
        d = run.dom.get(dom); r = d and d["robots"]
        if not r or r["status"] != 200 or not r["is_text"]: return 0
        if mode != "v6" and r.get("via") == "L0": return 0
        mb = r.get("mb_old", r["cf_managed"])   # týž matcher (T0: citlivý na velikost) na obou koncích, přepočet z blobů (Opus N9)
        if mode == "MB": return int(bool(mb))
        if mode == "M2": return int(bool(mb or r.get("bps") or r["content_signal"]))   # citlivost 18. 9.: M_B ∨ BPS ∨ M_C
        return int(bool(mb or r["content_signal"]))
    def did(run_b, pairs, mode="prereg"):
        out = {}
        for cls in ("cf_proxied", "no_cf"):
            ds = [dom for dom in pairs if ra.dom[dom]["cf_class"] == cls]
            out[cls] = ([M(run_b, x, mode) - M(ra, x, mode) for x in ds], len(ds))
        dcf, dno = out["cf_proxied"][0], out["no_cf"][0]
        est = (sum(dcf) / len(dcf) if dcf else 0) - (sum(dno) / len(dno) if dno else 0)
        rng = random.Random(7); bs = []
        for _ in range(1000):
            m1 = sum(dcf[rng.randrange(len(dcf))] for _ in range(len(dcf))) / len(dcf) if dcf else 0
            m2 = sum(dno[rng.randrange(len(dno))] for _ in range(len(dno))) / len(dno) if dno else 0
            bs.append(m1 - m2)
        bs.sort(); return est, bs[25], bs[974], out["cf_proxied"][1], out["no_cf"][1]
    common = [x for x in ra.dom if x in rb.dom]
    same = [x for x in common if ra.dom[x]["cf_class"] == rb.dom[x]["cf_class"] and (ra.dom[x]["fetch"].get("L2", {}).get("status") is not None)]
    mig = Counter((ra.dom[x]["cf_class"], rb.dom[x]["cf_class"]) for x in common if ra.dom[x]["cf_class"] != rb.dom[x]["cf_class"])
    L = []; w = L.append
    w(f"# Q5 delta markeru M (= M_B ∨ M_C dle obálky, cesta v5): `{a}` → `{b}` (ITT třída z {a}; šum: `{noise_b}`)\n")
    w("Bootstrap: jednotka doména, převzorkování zvlášť v každém rameni, 1000 replikací, seed 7 (fixováno v kódu před T1). Fallback robots přes Chrome (v6, `via=L0`) do pre-registrovaného čtení NEvstupuje (Opus reakce §2.1).\n")
    e, lo, hi, ncf, nno = did(rb, common)
    w(f"- **DiD (ITT, vše, pre-registrované čtení):** {100*e:+.2f} p.b. [95% CI {100*lo:+.2f}, {100*hi:+.2f}] · n cf_proxied {ncf}, no_cf {nno}")
    e2, lo2, hi2, _, _ = did(rb, same)
    w(f"- **DiD (podmíněná: stejná třída v obou, L2 odpověděla; Gemini #4):** {100*e2:+.2f} p.b. [{100*lo2:+.2f}, {100*hi2:+.2f}] · n {len(same)}")
    e6, lo6, hi6, _, _ = did(rb, common, "v6"); eB, loB, hiB, _, _ = did(rb, common, "MB")
    w(f"- **Citlivost — s Chrome fallbackem (v6):** {100*e6:+.2f} p.b. [{100*lo6:+.2f}, {100*hi6:+.2f}] · **jen M_B (čtení pro článek):** {100*eB:+.2f} p.b. [{100*loB:+.2f}, {100*hiB:+.2f}]")
    eM2, loM2, hiM2, _, _ = did(rb, common, "M2")
    nb = sum(1 for x in common if (rb.dom[x]["robots"] or {}).get("bps")); na_ = sum(1 for x in common if (ra.dom[x]["robots"] or {}).get("bps"))
    w(f"- **Citlivost 18. 9. — M_B ∨ BPS ∨ M_C (BPS = marker `Bot Preference Sync`, nástupce managed robots.txt):** {100*eM2:+.2f} p.b. [{100*loM2:+.2f}, {100*hiM2:+.2f}] · domén s BPS: A {na_}, B {nb}")
    def cnt(run, key): return sum(1 for x in common if ra.dom[x]["cf_class"] == "cf_proxied" and (run.dom[x]["robots"] or {}).get(key))
    w(f"- **Rozpad markeru mezi `cf_proxied` (Opus 18. 9.): M_B A {cnt(ra,'mb_old')} → B {cnt(rb,'mb_old')} · BPS A {cnt(ra,'bps')} → B {cnt(rb,'bps')} · `Content-signal:` uvnitř bloku Cloudflare A {cnt(ra,'mc_in_block')} → B {cnt(rb,'mc_in_block')} · mimo blok A {cnt(ra,'mc_out_block')} → B {cnt(rb,'mc_out_block')}**")
    if rn:
        pool = [x for x in common if x in rn.dom and x in rna.dom]
        en, lon, hin, _, _ = did(rn, pool)
        # hrubý obrat per rameno (Opus reakce §2.2): podíl domén ramene s M@A ≠ M@noise_b; šum = max
        flips = {}
        for cls in ("cf_proxied", "no_cf"):
            ds = [x for x in pool if ra.dom[x]["cf_class"] == cls]
            flips[cls] = (sum(1 for x in ds if M(rna, x) != M(rn, x)) / len(ds) if ds else 0.0, len(ds))
        sum_noise = max(flips["cf_proxied"][0], flips["no_cf"][0]) or (1 / max(1, min(flips["cf_proxied"][1], flips["no_cf"][1])))
        w(f"- **Šumové dno = hrubý obrat M mezi {noise_a if rna is not ra else a} a {noise_b}:** cf_proxied {100*flips['cf_proxied'][0]:.2f} % (n {flips['cf_proxied'][1]}), no_cf {100*flips['no_cf'][0]:.2f} % (n {flips['no_cf'][1]}) → šum = {100*sum_noise:.2f} p.b.; čistý DiD({a}→{noise_b}) = {100*en:+.2f} p.b. [{100*lon:+.2f}, {100*hin:+.2f}] jen jako kontrola směru")
        ci_pos = lo > 0; above = e > c * sum_noise
        verdict = {(True, True): "SKOK", (False, False): "žádný skok nad šumem", (True, False): "HRANIČNÍ: CI > 0, ale pod prahem c·šum", (False, True): "HRANIČNÍ: nad prahem, ale CI obsahuje 0"}[(ci_pos, above)]
        w(f"- **Pravidlo (c = {c}, `rfc/2026-09-15-prahy-cf-T0.md`):** dolní mez CI > 0: {ci_pos}; DiD > c·šum ({100*c*sum_noise:.2f} p.b.): {above} → **{verdict}**")
        w("- Mez: obrat mezi dvěma měřeními téhož dne je spodní odhad šumu pro odstup dvou dnů.")
    w("- **Migrace tříd A→B:** " + (", ".join(f"{k[0]}→{k[1]}: {v}" for k, v in mig.most_common()) or "žádné"))
    text = "\n".join(L) + "\n"
    if out: os.makedirs(os.path.dirname(out) or ".", exist_ok=True); open(out, "w").write(text); print(f"delta → {out}")
    print(text)

# ---------------------------------------------------------------- Q8 (RFC dodatek 18. 9.): chování hrany, ramena podle markeru
Q8_RUNGS = ["L4a", "L4b", "L4c", "L4g", "L3", "L2", "L0"]
def _q8_load(db, run):
    cls = {d: c for d, c in db.execute("SELECT domain,cf_class FROM domain_summary WHERE run_id=?", (run,))}
    rob = {r[0]: r[1:] for r in db.execute("SELECT domain,status,is_text,via,cf_managed,content_signal FROM robots WHERE run_id=?", (run,))}
    fet = {(d, rg): (st, ch, p, err, sig) for d, rg, st, ch, p, err, sig in db.execute("SELECT domain,rung,status,challenge,pass,error,block_sig FROM fetch WHERE run_id=?", (run,))}
    return cls, rob, fet
def _q8_cause(f):
    if f is None: return "chybi"
    st, ch, p, err, sig = f
    if p: return "pass"
    if err == "skipped_unreachable": return "nedostupne"
    if err: return "timeout/spojeni"
    if ch: return "challenge"
    st = st or 0
    if st == 403: return "403"
    if st == 429: return "429"
    if st >= 500: return "5xx"
    if st >= 400: return "jine 4xx"
    return "jine"
def _q8_strict(f):
    c = _q8_cause(f)
    if c == "pass": return "pass"
    if c in ("403", "challenge") or (f and f[4]): return "blok"
    return "vypadek"
def _logit(p): p = min(max(p, 1e-6), 1 - 1e-6); return math.log(p / (1 - p))
def q8_arms(db, run_a, run_noise, run_b):
    """Ramena fixovaná ze stavu T0a (run_a), T0b (run_noise) a T1 (run_b); třída cf_proxied z run_a (ITT)."""
    ca, ra, _ = _q8_load(db, run_a); cn, rn, _ = _q8_load(db, run_noise); cb, rb, _ = _q8_load(db, run_b)
    mb = lambda r, d: bool(r.get(d) and r[d][3])
    mc = lambda r, d: bool(r.get(d) and r[d][4] and not r[d][3] and r[d][0] == 200 and r[d][1])
    cf = [d for d in ca if ca[d] == "cf_proxied"]; inb = set(cb)
    arms = {"ztracene": [d for d in cf if mb(ra, d) and d in inb and not mb(rb, d)],
            "udrzene": [d for d in cf if mb(ra, d) and mb(rb, d)],
            "MC_bez_MB": [d for d in cf if not mb(ra, d) and mc(ra, d) and d in inb],
            "nikdy": [d for d in cf if d in inb and not mb(ra, d) and not mb(rn, d) and not mc(ra, d)],
            "placebo_no_cf": [d for d in ca if ca[d] == "no_cf" and d in inb]}
    return arms
def q8(db, run_a, run_noise, run_b, run_c, out, reps=1000, seed=7):
    """Q8a = DiD run_a→run_c, Q8b = DiD run_b→run_c; ramena z run_a/run_noise/run_b. Pro kontrolu run_c = run_b reprodukuje předběžné čtení T0a→T1."""
    arms = q8_arms(db, run_a, run_noise, run_b)
    F = {}
    for run in {run_a, run_b, run_c}:
        _, _, fet = _q8_load(db, run)
        for k, v in fet.items(): F[(run,) + k] = v
    def rate(ds, run, rg, mode):
        xs = [F.get((run, d, rg)) for d in ds]; xs = [x for x in xs if x is not None and x[3] != "skipped_unreachable"]
        if mode == "full": fails, n = sum(1 for x in xs if not x[2]), len(xs)
        else:
            ys = [y for y in (_q8_strict(x) for x in xs) if y != "vypadek"]; fails, n = sum(1 for y in ys if y == "blok"), len(ys)
        return (fails / n if n else None, n)
    def pair(ds, r1, r2, rg):
        v = []
        for d in ds:
            x, y = F.get((r1, d, rg)), F.get((r2, d, rg))
            if x is None or y is None or x[3] == "skipped_unreachable" or y[3] == "skipped_unreachable": continue
            v.append((0 if x[2] else 1, 0 if y[2] else 1))
        return v
    rng = random.Random(seed)
    def boot(z, n):
        if not z or not n: return None
        rs = []
        for _ in range(reps):
            zs = [z[rng.randrange(len(z))] for _ in z]; ns = [n[rng.randrange(len(n))] for _ in n]
            rs.append(100 * (sum(b - a for a, b in zs) / len(zs) - sum(b - a for a, b in ns) / len(ns)))
        rs.sort(); return [round(rs[int(0.025 * reps)], 2), round(rs[int(0.975 * reps) - 1], 2)]
    res = {"ramena_n": {k: len(v) for k, v in arms.items()}, "runs": {"a": run_a, "noise": run_noise, "b": run_b, "c": run_c}, "Q8a": {}, "Q8b": {}}
    for key, r1 in (("Q8a", run_a), ("Q8b", run_b)):
        for rg in Q8_RUNGS:
            T = {}
            for arm, ds in arms.items():
                row = {}
                for mode in ("full", "strict"):
                    p1, n1 = rate(ds, r1, rg, mode); p2, n2 = rate(ds, run_c, rg, mode)
                    row[mode] = {"h1": None if p1 is None else round(100 * p1, 1), "h2": None if p2 is None else round(100 * p2, 1), "n1": n1, "n2": n2,
                                 "delta_pb": None if p1 is None or p2 is None else round(100 * (p2 - p1), 2),
                                 "delta_logodds": None if not p1 or not p2 else round(_logit(p2) - _logit(p1), 3)}
                tm = Counter(("P" if a == 0 else "F") + ">" + ("P" if b == 0 else "F") for a, b in pair(ds, r1, run_c, rg))
                bc = tm["P>F"] + tm["F>P"]; row["prechod"] = dict(tm); row["mcnemar_chi2"] = round(((abs(tm["P>F"] - tm["F>P"]) - 1) ** 2 / bc) if bc else 0, 1)
                row["rozpad_1"] = dict(Counter(_q8_cause(F.get((r1, d, rg))) for d in ds)); row["rozpad_2"] = dict(Counter(_q8_cause(F.get((run_c, d, rg))) for d in ds))
                T[arm] = row
            for arm in T:
                for mode in ("full", "strict"):
                    dv, dn = T[arm][mode]["delta_pb"], T["nikdy"][mode]["delta_pb"]
                    T[arm][mode]["DiD_vs_nikdy_pb"] = None if dv is None or dn is None else round(dv - dn, 2)
                    lv, ln = T[arm][mode]["delta_logodds"], T["nikdy"][mode]["delta_logodds"]
                    T[arm][mode]["DiD_vs_nikdy_logodds"] = None if lv is None or ln is None else round(lv - ln, 3)
                T[arm]["CI95_DiD_vs_nikdy_full"] = boot(pair(arms[arm], r1, run_c, rg), pair(arms["nikdy"], r1, run_c, rg)) if arm != "nikdy" else None
            res[key][rg] = T
    ads = {d: (v or 0) > 0 for d, v in db.execute("SELECT domain,valid_lines FROM ads WHERE run_id=?", (run_a,))}
    res["ads_interakce_L4a_Q8a"] = {}
    for arm in ("ztracene", "nikdy"):
        for lab, ds in (("ads", [d for d in arms[arm] if ads.get(d)]), ("bez_ads", [d for d in arms[arm] if not ads.get(d)])):
            p1, _ = rate(ds, run_a, "L4a", "full"); p2, _ = rate(ds, run_c, "L4a", "full")
            res["ads_interakce_L4a_Q8a"][f"{arm}/{lab}"] = {"n": len(ds), "h1": None if p1 is None else round(100 * p1, 1), "h2": None if p2 is None else round(100 * p2, 1)}
    L = [f"# Q8 (RFC dodatek 18. 9.): chování hrany — Q8a {run_a} → {run_c}, Q8b {run_b} → {run_c}; ramena z {run_a}/{run_noise}/{run_b}", "",
         "Ramena: " + ", ".join(f"{k} {v}" for k, v in res["ramena_n"].items()) + ". `pass` ze statusu a titulku; přísné = 403 ∨ challenge ∨ bloková stránka, výpadky vyřazeny. Bootstrap per rameno, " + f"{reps} replikací, seed {seed}.", ""]
    for key in ("Q8a", "Q8b"):
        L += [f"## {key}: hladiny ¬pass (%) h1 → h2 per rameno (plné čtení) a DiD proti rameni nikdy", "", "| rameno | " + " | ".join(Q8_RUNGS) + " |", "|---|" + "---|" * len(Q8_RUNGS)]
        for arm in arms:
            L.append(f"| {arm} ({res['ramena_n'][arm]}) | " + " | ".join(f"{res[key][rg][arm]['full']['h1']} → {res[key][rg][arm]['full']['h2']}" for rg in Q8_RUNGS) + " |")
        L += ["", "| příčka | DiD ztracené − nikdy (p.b.) | 95% CI | přísné DiD | log-šance DiD | přechody ztracené (P>F / F>P) | McNemar χ² |", "|---|---|---|---|---|---|---|"]
        for rg in Q8_RUNGS:
            z = res[key][rg]["ztracene"]; ci = z["CI95_DiD_vs_nikdy_full"]
            L.append(f"| {rg} | {z['full']['DiD_vs_nikdy_pb']} | {ci} | {z['strict']['DiD_vs_nikdy_pb']} | {z['full']['DiD_vs_nikdy_logodds']} | {z['prechod'].get('P>F',0)} / {z['prechod'].get('F>P',0)} | {z['mcnemar_chi2']} |")
        z = res[key]["L4a"]["ztracene"]; L += ["", f"Rozpad ¬pass L4a ztracené: {z['rozpad_1']} → {z['rozpad_2']}", ""]
    L.append("ads.txt × rameno (L4a, Q8a): " + "; ".join(f"{k} n {v['n']}: {v['h1']} → {v['h2']}" for k, v in res["ads_interakce_L4a_Q8a"].items()))
    text = "\n".join(L) + "\n"
    if out:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True); open(out, "w").write(text); json.dump(res, open(out.rsplit(".", 1)[0] + ".json", "w"), indent=1, ensure_ascii=False); print(f"q8 → {out}")
    print(text)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report"); r.add_argument("--db", required=True); r.add_argument("--run-id", required=True); r.add_argument("--out")
    n = sub.add_parser("noise"); n.add_argument("--db", required=True); n.add_argument("--run-a", required=True); n.add_argument("--run-b", required=True); n.add_argument("--out")
    dl = sub.add_parser("delta"); dl.add_argument("--db", required=True); dl.add_argument("--run-a", required=True); dl.add_argument("--run-b", required=True); dl.add_argument("--noise-b"); dl.add_argument("--noise-a", help="první měření dvojice šumového dna (výchozí = run-a); pro dvojice s A ≠ T0a zadat T0a"); dl.add_argument("--c", type=float, default=3.0); dl.add_argument("--out")
    q = sub.add_parser("q8"); q.add_argument("--db", required=True); q.add_argument("--run-a", required=True); q.add_argument("--run-noise", required=True); q.add_argument("--run-b", required=True); q.add_argument("--run-c", required=True); q.add_argument("--out")
    a = ap.parse_args(); db = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    if a.cmd == "report": report(Run(db, a.run_id), a.out)
    elif a.cmd == "noise": noise(db, a.run_a, a.run_b, a.out)
    elif a.cmd == "q8": q8(db, a.run_a, a.run_noise, a.run_b, a.run_c, a.out)
    else: delta(db, a.run_a, a.run_b, a.noise_b, a.out, a.c, a.noise_a)
