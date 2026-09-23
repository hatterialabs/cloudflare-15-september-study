#!/usr/bin/env python3
"""aditivita — porovná cestu v5 (starý skript) a v6.1 (nový skript) na témže vzorku (Opus reakce §2.1.2).
Porovnává per doména: CF třída, robots status (cesta v5 = via L3/L2), M = M_B∨M_C, train_blocked, pass per HTTP příčka.
  python3 scripts/aditivita.py --v5 /mnt/backup/cfstudy/aditivita/v5.sqlite --v6 /mnt/backup/cfstudy/aditivita/v6.sqlite --out reviews/2026-09-16-aditivita-v5-v6.md
"""
import argparse, sqlite3, json, collections, os

def load(path, run_id):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    cols = {c[1] for c in db.execute("PRAGMA table_info(robots)")}
    via_expr = "via" if "via" in cols else "NULL"
    d = {}
    for dom, cls in db.execute("SELECT domain, cf_class FROM domain_summary WHERE run_id=?", (run_id,)):
        d[dom] = {"cls": cls, "rungs": {}, "robots": None}
    for dom, rung, p, st in db.execute("SELECT domain, rung, pass, status FROM fetch WHERE run_id=?", (run_id,)):
        if dom in d: d[dom]["rungs"][rung] = (p, st)
    for row in db.execute(f"SELECT domain, status, is_text, cf_managed, content_signal, train_blocked, {via_expr} FROM robots WHERE run_id=?", (run_id,)):
        if row[0] in d: d[row[0]]["robots"] = dict(zip(["status", "is_text", "cf_managed", "content_signal", "train_blocked", "via"], row[1:]))
    return d

def M(r):  # pre-registrované čtení: jen cesta v5 (via L3/L2 nebo None u v5), robots 200 text
    if not r or r["status"] != 200 or not r["is_text"] or r.get("via") == "L0": return 0
    return int(bool(r["cf_managed"] or r["content_signal"]))

def main(a):
    v5, v6 = load(a.v5, "adit-v5"), load(a.v6, "adit-v6")
    common = sorted(set(v5) & set(v6)); L = []; w = L.append
    w(f"# Kontrola aditivity v5 (8ad033a) vs v6.1 (09954a4), vzorek {len(common)} domén (seed 20260916), bez Chrome\n")
    w("Porovnání pre-registrovaných čtení cesty v5 na obou verzích; práh shody = šum T0a/T0b (příčky ≤ 1,7 p.b., robots příznaky ≤ 0,2 p.b., třída ≤ 0,2 p.b.).\n")
    w("| veličina | neshod | z n | podíl |"); w("|---|---|---|---|")
    def row(lab, pred, pool=None):
        pool = pool or common; k = sum(1 for x in pool if pred(v5[x], v6[x])); w(f"| {lab} | {k} | {len(pool)} | {100*k/len(pool):.1f} % |"); return k
    row("CF třída", lambda x, y: x["cls"] != y["cls"])
    row("robots status (v5 cesta)", lambda x, y: (x["robots"] or {}).get("status") != (y["robots"] or {}).get("status"))
    row("M = M_B∨M_C (v5 cesta)", lambda x, y: M(x["robots"]) != M(y["robots"]))
    row("train_blocked", lambda x, y: bool((x["robots"] or {}).get("train_blocked")) != bool((y["robots"] or {}).get("train_blocked")))
    for r in ("L2", "L3", "L3r", "L4a", "L4b", "L4c", "L4g"):
        row(f"{r} pass", lambda x, y, r=r: bool(x["rungs"].get(r, (0,))[0]) != bool(y["rungs"].get(r, (0,))[0]), [x for x in common if r in v5[x]["rungs"] and r in v6[x]["rungs"]])
    fb = sum(1 for x in common if (v6[x]["robots"] or {}).get("via") == "L0")
    w(f"\nChrome fallback robots v v6 použit u {fb} domén (v tomto běhu bez Chrome → fallback nedostupný, tedy 0 očekáváno).")
    w("\nČtení: neshody v jednotkách procent u pass jsou šum mezi dvěma běhy (viz T0a/T0b 1,0–1,7 p.b.); neshody u tříd/robots nad 0,2 p.b. by znamenaly změnu měřidla.")
    text = "\n".join(L) + "\n"
    if a.out: os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True); open(a.out, "w").write(text)
    print(text)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--v5", required=True); ap.add_argument("--v6", required=True); ap.add_argument("--out"); main(ap.parse_args())
