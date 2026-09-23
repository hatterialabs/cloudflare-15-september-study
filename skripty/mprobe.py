#!/usr/bin/env python3
"""mprobe — denní lehká sonda markeru M (Cloudflare managed robots.txt) do T2.
Vzorek: všechny domény s M_B v T0a + 300 náhodných cf_proxied bez M + 200 no_cf (seed 20260916, fixní seznam v runs/controls/mprobe/sample.txt).
  python3 scripts/mprobe.py --db /mnt/backup/cfstudy/cfstudy.sqlite --out runs/controls/mprobe
Výstup: <out>/<datum>.jsonl (doména, status, cf-cache-status, kind ∈ MANAGED/CS/origin/html/404/err) + řádek do <out>/summary.md.
"""
import argparse, sqlite3, random, json, os, datetime, collections, concurrent.futures as cf, httpx
UA="torumata-probe/0.1 (+https://torumata.com/probe)"
UA_GPT="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)"   # týž řetězec jako L4a v cfprobe
import re as _re
def sample(db, path):
    if os.path.exists(path): return [l.split('\t') for l in open(path).read().splitlines()]
    c=sqlite3.connect(f"file:{db}?mode=ro",uri=True); A='cf-T0a-2026-09-14-home-r5'
    cls={d:k for d,k in c.execute("SELECT domain,cf_class FROM domain_summary WHERE run_id=?",(A,))}
    mb={d for d,m in c.execute("SELECT domain,cf_managed FROM robots WHERE run_id=?",(A,)) if m}
    mc={d for d,m in c.execute("SELECT domain,content_signal FROM robots WHERE run_id=?",(A,)) if m}
    rnd=random.Random(20260916)
    cfp=sorted(d for d,k in cls.items() if k=='cf_proxied' and d not in mb and d not in mc); ncf=sorted(d for d,k in cls.items() if k=='no_cf')
    rows=[(d,'mb') for d in sorted(mb)]+[(d,'cf_noM') for d in rnd.sample(cfp,300)]+[(d,'no_cf') for d in rnd.sample(ncf,200)]
    os.makedirs(os.path.dirname(path),exist_ok=True); open(path,'w').write("\n".join(f"{d}\t{g}" for d,g in rows)+"\n"); return rows
def probe(d):
    try:
        with httpx.Client(follow_redirects=True,timeout=15,headers={"User-Agent":UA}) as c: r=c.get(f"https://{d}/robots.txt")
        b=r.text[:200000].lower(); cs=r.headers.get('cf-cache-status','-')
        kind='MANAGED' if 'cloudflare managed content' in b else ('BPS' if 'bot preference sync' in b else ('CS' if 'content-signal:' in b else ('html' if '<html' in b[:500] else ('404' if r.status_code==404 else 'origin'))))
        return {"domain":d,"status":r.status_code,"cache":cs,"kind":kind,"len":len(r.content),"server":r.headers.get('server','')}
    except Exception as e: return {"domain":d,"status":None,"cache":"-","kind":"err","err":type(e).__name__}
def edge(d):
    """test D (RFC 18. 9.): GET domovské stránky s UA GPTBot; pass = 2xx/3xx bez challenge."""
    try:
        with httpx.Client(follow_redirects=True,timeout=15,headers={"User-Agent":UA_GPT}) as c: r=c.get(f"https://{d}/")
        ch=int(r.headers.get('cf-mitigated','')=='challenge' or bool(_re.search(r'Just a moment|challenge-platform|cf-chl', r.text[:20000])))
        k='challenge' if ch else ('pass' if r.status_code<400 else ('403' if r.status_code==403 else ('429' if r.status_code==429 else ('5xx' if r.status_code>=500 else 'jine4xx'))))
        return {"e_status":r.status_code,"e_kind":k,"e_ray":r.headers.get('cf-ray','')}
    except Exception as e: return {"e_status":None,"e_kind":"err","e_err":type(e).__name__}
def main(a):
    rows=sample(a.db,os.path.join(a.out,'sample.txt')); day=datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H%MZ')
    grp={d:g for d,g in rows}
    with cf.ThreadPoolExecutor(a.par) as ex: res=list(ex.map(probe,[d for d,_ in rows]))
    edge_doms=[d for d,g in rows if g in ('mb','cf_noM')]
    with cf.ThreadPoolExecutor(a.par) as ex: eres=dict(zip(edge_doms, ex.map(edge, edge_doms)))
    for r in res:
        if r['domain'] in eres: r.update(eres[r['domain']])
    with open(os.path.join(a.out,f"{day}.jsonl"),'w') as f:
        for r in res: r['group']=grp[r['domain']]; f.write(json.dumps(r,ensure_ascii=False)+"\n")
    tab=collections.defaultdict(collections.Counter)
    for r in res: tab[r['group']][r['kind']]+=1
    etab=collections.defaultdict(collections.Counter)
    for r in res:
        if 'e_kind' in r: etab[r['group']][r['e_kind']]+=1
    line=f"| {day} | "+" | ".join(f"{g}: "+", ".join(f"{k} {n}" for k,n in sorted(tab[g].items())) for g in ('mb','cf_noM','no_cf'))+" | hrana GPTBot "+" · ".join(f"{g}: "+", ".join(f"{k} {n}" for k,n in sorted(etab[g].items())) for g in ('mb','cf_noM'))+" |"
    sp=os.path.join(a.out,'summary.md')
    if not os.path.exists(sp): open(sp,'w').write("# mprobe — denní sonda markeru M (UA torumata-probe, robots.txt, follow redirects)\n\n| kdy (UTC) | mb (M_B v T0a) | cf_noM | no_cf | hrana (od 18. 9.) |\n|---|---|---|---|---|\n")
    open(sp,'a').write(line+"\n"); print(line)
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--db',required=True); ap.add_argument('--out',required=True); ap.add_argument('--par',type=int,default=24); main(ap.parse_args())
