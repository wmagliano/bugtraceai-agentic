#!/usr/bin/env python3
from __future__ import annotations
import json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from analysis_queue import ensure_schema, add_item
from url_blacklist import is_blacklisted_url, blacklist_reason
from black_vulns import is_black_vuln, black_vuln_reason

KNOWLEDGE = Path('data/knowledge.json')
DEFAULT_STATIC = ['css','js','png','jpg','jpeg','gif','svg','ico','woff','woff2','ttf','map','mp4','webm','mp3','wav']

def utc_now(): return datetime.now(timezone.utc).isoformat()

def load_k():
    try: return json.loads(KNOWLEDGE.read_text(encoding='utf-8'))
    except Exception: return {}

def save_k(k):
    KNOWLEDGE.parent.mkdir(parents=True, exist_ok=True)
    KNOWLEDGE.write_text(json.dumps(k, indent=2, ensure_ascii=False), encoding='utf-8')

def normalize(url:str|None):
    if not isinstance(url,str) or not url.strip(): return None
    url=url.strip()
    if not url.startswith(('http://','https://')): return url
    p=urlsplit(url)
    path=re.sub(r'/{2,}','/',p.path or '/')
    # Los fragments se conservan o descartan por configuración, nunca por tipo de aplicación.
    fragment=p.fragment if os.getenv('BUGTRACEAI_DISCOVERY_FRAGMENT_POLICY','discard')=='preserve' else ''
    return urlunsplit((p.scheme.lower(),p.netloc.lower(),path,p.query,fragment))

def same_origin(url, base):
    try:
        a,b=urlsplit(url),urlsplit(base)
        return (a.scheme.lower(),a.netloc.lower())==(b.scheme.lower(),b.netloc.lower())
    except Exception: return False

def is_static(url):
    raw=os.getenv('BUGTRACEAI_DISCOVERY_STATIC_EXTENSIONS_JSON','')
    try: exts=json.loads(raw) if raw else DEFAULT_STATIC
    except Exception: exts=DEFAULT_STATIC
    path=urlsplit(url).path.lower()
    suffix=path.rsplit('.',1)[-1] if '.' in path.rsplit('/',1)[-1] else ''
    return suffix in {str(x).lower().lstrip('.') for x in exts}

def register_urls(k, source_url, urls, interactive=True):
    mode=os.getenv('BUGTRACEAI_DISCOVERY_MODE','auto').strip().lower()
    if mode not in {'auto','operator'}: mode='auto'
    base=os.getenv('BUGTRACEAI_TARGET_BASE') or ((k.get('scope') or {}).get('target_base')) or ''
    same_only=os.getenv('BUGTRACEAI_DISCOVERY_SAME_ORIGIN','1').lower() in {'1','true','yes','on'}
    max_urls=int(os.getenv('BUGTRACEAI_DISCOVERY_MAX_URLS','500'))
    static_policy=os.getenv('BUGTRACEAI_DISCOVERY_STATIC_POLICY','ignore').lower()
    disc=k.setdefault('url_discovery',{})
    disc['mode']=mode
    decisions=disc.setdefault('decisions',{})
    events=disc.setdefault('events',[])
    ensure_schema(k)
    candidates=[x.get('entry_url') for x in k.get('analysis_queue',[]) if isinstance(x,dict) and x.get('entry_url')]
    visited={normalize(x) for x in (k.get('visited_urls') or []) if normalize(x)}
    completed=set()
    for item in k.get('completed_urls') or []:
        u=item.get('url') if isinstance(item,dict) else item
        if normalize(u): completed.add(normalize(u))
    added=[]; rejected=[]
    for raw in urls or []:
        url=normalize(raw)
        if not url or url==normalize(source_url): continue
        if url in visited or url in completed or url in candidates: continue
        if url in decisions:
            if decisions[url].get('decision')=='add' and len(candidates)<max_urls:
                # Una decisión persistida autoriza la URL, pero el Analysis Item
                # puede haber sido eliminado por un reset. Reconstruirlo siempre.
                _,created=add_item(k,url,'persisted_discovery_decision')
                if url not in candidates:
                    candidates.append(url)
                if created:
                    added.append(url)
            continue
        reason=None
        if is_blacklisted_url(url): reason=blacklist_reason(url)
        elif is_black_vuln(url): reason=black_vuln_reason(url)
        if same_only and base and not same_origin(url,base): reason='outside_origin'
        elif static_policy=='ignore' and is_static(url): reason='static_resource'
        elif len(candidates)>=max_urls: reason='max_urls_reached'
        if reason:
            decisions[url]={'decision':'reject','reason':reason,'source_url':source_url,'timestamp':utc_now(),'mode':'technical'}
            rejected.append(url); continue
        decision='add'
        if mode=='operator' and interactive:
            print('\n[NEW URL DISCOVERED]')
            print('URL:',url)
            print('Detectada desde:',source_url or '(desconocido)')
            print('1) Agregar para análisis')
            print('2) No agregar para análisis')
            while True:
                try: answer=input('Selección [1/2]: ').strip().lower()
                except EOFError: answer='2'
                if answer in {'1','add','yes','y','si','sí'}: decision='add'; break
                if answer in {'2','no','n','reject'}: decision='reject'; break
                print('Opción inválida. Use 1 o 2.')
        elif mode=='operator' and not interactive:
            decision='reject'
        decisions[url]={'decision':decision,'reason':'operator' if mode=='operator' else 'auto_in_scope','source_url':source_url,'timestamp':utc_now(),'mode':mode}
        events.append({'url':url,'source_url':source_url,'decision':decision,'timestamp':utc_now(),'mode':mode})
        if decision=='add':
            _,created=add_item(k,url,'discovery_'+mode)
            if created: candidates.append(url); added.append(url)
        else: rejected.append(url)
    # Preserva orden de descubrimiento y evita duplicados.
    seen=set(); ordered=[]
    for u in candidates:
        if u and u not in seen: seen.add(u); ordered.append(u)
    allowed=set(ordered[:max_urls])
    k['analysis_queue']=[x for x in k.get('analysis_queue',[]) if x.get('entry_url') in allowed]
    k['candidate_urls']=[x.get('entry_url') for x in k['analysis_queue']]
    disc['events']=events[-1000:]
    disc['approved_count']=sum(1 for x in decisions.values() if x.get('decision')=='add')
    disc['rejected_count']=sum(1 for x in decisions.values() if x.get('decision')=='reject')
    return added,rejected

def process_existing(interactive=True):
    k=load_k()
    ensure_schema(k)
    # v1.9.0.2: reconciliación no destructiva. Nunca vaciar analysis_queue.
    # Las URLs ya aprobadas permanecen como Analysis Items; únicamente se
    # reconstruyen elementos faltantes a partir del espejo legacy.
    existing=[]
    for item in k.get('analysis_queue') or []:
        if isinstance(item,dict) and item.get('entry_url'):
            existing.append(item['entry_url'])
    for url in k.get('candidate_urls') or []:
        if url not in existing:
            existing.append(url)

    before=len(k.get('analysis_queue') or [])
    rebuilt=0
    for url in existing:
        _,created=add_item(k,url,'discovery_reconcile')
        if created:
            rebuilt+=1

    # Sincroniza el espejo, pero no vuelve a someter URLs aprobadas a decisiones
    # antiguas ni elimina expedientes válidos.
    ensure_schema(k, migrate_legacy=True)
    save_k(k)
    print(json.dumps({
        'mode':os.getenv('BUGTRACEAI_DISCOVERY_MODE','auto'),
        'added':rebuilt,
        'rejected':0,
        'analysis_items':len(k.get('analysis_queue') or []),
        'preserved':before
    },indent=2,ensure_ascii=False))

if __name__=='__main__':
    interactive='--non-interactive' not in sys.argv
    process_existing(interactive=interactive)
