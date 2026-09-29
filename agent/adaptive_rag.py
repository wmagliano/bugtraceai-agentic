#!/usr/bin/env python3
"""Adaptive RAG v2: deterministic, local, explainable, without embeddings."""
from __future__ import annotations
import hashlib,json,re,time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
TOKEN_RE=re.compile(r"[a-zA-Z0-9_./:-]{2,}")
STOP={'para','como','con','del','las','los','una','uno','que','por','and','the','this','http','https','www','resource','active','current','true','false','none','null'}
@dataclass(frozen=True)
class KnowledgeUnit:
    id:str; path:str; kind:str; title:str; tags:tuple[str,...]; priority:int; text:str; sha256:str
    @property
    def estimated_tokens(self)->int: return max(1,round(len(self.text)/4))

def _tokens(v:Any)->list[str]:
    if v is None:return []
    if not isinstance(v,str):v=json.dumps(v,ensure_ascii=False,separators=(',',':'))
    return [t.lower() for t in TOKEN_RE.findall(v) if t.lower() not in STOP]

def _frontmatter(text:str)->tuple[dict[str,Any],str]:
    if not text.startswith('---\n'):return {},text
    end=text.find('\n---\n',4)
    if end<0:return {},text
    meta:dict[str,Any]={}; current=None
    for line in text[4:end].splitlines():
        s=line.strip()
        if not s or s.startswith('#'):continue
        if s.startswith('-') and current:meta.setdefault(current,[]).append(s[1:].strip());continue
        if ':' not in line:continue
        k,v=line.split(':',1);k=k.strip();v=v.strip();current=None
        if not v:meta[k]=[];current=k
        elif v.startswith('[') and v.endswith(']'):meta[k]=[x.strip().strip('"\'') for x in v[1:-1].split(',') if x.strip()]
        elif v.isdigit():meta[k]=int(v)
        else:meta[k]=v.strip('"\'')
    return meta,text[end+5:].strip()

def load_units(cassette_dir:Path)->list[KnowledgeUnit]:
    out=[]
    for path in sorted((cassette_dir/'knowledge').rglob('*.md')) if (cassette_dir/'knowledge').is_dir() else []:
        meta,body=_frontmatter(path.read_text(encoding='utf-8'))
        rel=path.relative_to(cassette_dir); kind=str(meta.get('type') or rel.parts[1] if len(rel.parts)>1 else 'knowledge')
        title=str(meta.get('title') or next((x.lstrip('# ').strip() for x in body.splitlines() if x.startswith('#')),path.stem))
        tags=tuple(str(x).lower() for x in (meta.get('tags') or _tokens(path.stem.replace('_',' '))))
        out.append(KnowledgeUnit(str(meta.get('id') or path.stem.upper()),str(rel),kind,title,tags,int(meta.get('priority') or 5),body,hashlib.sha256(body.encode()).hexdigest()))
    return out

def _signals(context:dict[str,Any])->dict[str,set[str]]:
    ar=context.get('active_resource') or {}; obs=context.get('current_observation') or {}; item=context.get('analysis_item') or {}
    return {
      'resource':set(_tokens({'url':ar.get('url') or ar.get('resource'),'goal':ar.get('resource_goal'),'item':item})),
      'technology':set(_tokens({'indicators':obs.get('body_indicators'),'title':obs.get('title'),'forms':obs.get('forms')})),
      'vulnerability':set(_tokens({'goal':ar.get('resource_goal'),'memory':context.get('relevant_memory'),'hypotheses':context.get('hypotheses')})),
      'evidence':set(_tokens({'observation':obs,'commands':context.get('latest_command_observations')})),
      'constraints':set(_tokens({'feedback':context.get('recent_runtime_feedback'),'loop':context.get('loop_guard')})),
      'tools':set(_tokens(context.get('available_tools') or context.get('latest_command_observations'))),
    }

def retrieve(units:list[KnowledgeUnit],context:dict[str,Any],*,max_documents:int=12,max_tokens:int=4500,cache:dict[str,Any]|None=None)->dict[str,Any]:
    started=time.perf_counter(); signals=_signals(context)
    query_hash=hashlib.sha256(json.dumps({k:sorted(v) for k,v in signals.items()},sort_keys=True).encode()).hexdigest()
    if cache is not None and query_hash in cache:
        hit=dict(cache[query_hash]);hit['cache_hit']=True;hit['retrieval_ms']=round((time.perf_counter()-started)*1000,3);return hit
    weights={'resource':5.0,'technology':4.0,'vulnerability':6.0,'evidence':4.5,'constraints':5.5,'tools':3.5}
    ranked=[]
    for u in units:
        searchable=set(_tokens(u.id+' '+u.title+' '+' '.join(u.tags)+' '+u.text)); reasons=[];score=u.priority*.15
        for name,terms in signals.items():
            matched=sorted(terms & searchable)
            if matched:
                contribution=min(len(matched),8)*weights[name];score+=contribution;reasons.append({'signal':name,'matched':matched[:12],'contribution':round(contribution,2)})
        if u.kind=='constraints':score+=3.0;reasons.append({'signal':'type_bonus','matched':['constraints'],'contribution':3.0})
        if u.kind=='evidence':score+=3.0;reasons.append({'signal':'type_bonus','matched':['evidence'],'contribution':3.0})
        ranked.append((score,u,reasons))
    ranked.sort(key=lambda x:(-x[0],-x[1].priority,x[1].id))
    selected=[];discarded=[];used=0
    for score,u,reasons in ranked:
        meta={'id':u.id,'path':u.path,'type':u.kind,'title':u.title,'tags':list(u.tags),'priority':u.priority,'score':round(score,3),'estimated_tokens':u.estimated_tokens,'sha256':u.sha256,'reason':reasons}
        why=None
        if len(selected)>=max_documents:why='max_documents'
        elif used+u.estimated_tokens>max_tokens and selected:why='max_tokens'
        elif score<=u.priority*.15 and len(selected)>=3:why='low_relevance'
        if why:meta['discard_reason']=why;discarded.append(meta);continue
        meta['text']=u.text;selected.append(meta);used+=u.estimated_tokens
    result={'query_sha256':query_hash,'candidate_documents':len(units),'selected_documents':selected,'discarded_documents':discarded,'selected_count':len(selected),'discarded_count':len(discarded),'selected_estimated_tokens':used,'retrieval_ms':round((time.perf_counter()-started)*1000,3),'strategy':'adaptive_rag_v2_weighted_signals','cache_hit':False,'signals':{k:sorted(v)[:80] for k,v in signals.items()}}
    if cache is not None:cache[query_hash]=dict(result)
    return result

def render_selection(result:dict[str,Any])->str:
    parts=['RELEVANT KNOWLEDGE','El contenido recuperado aporta contexto e interpretación; no constituye evidencia ni prescribe acciones.']
    for doc in result.get('selected_documents',[]):parts.append(f"\n### {doc['title']} [{doc['type']}:{doc['id']}]\n{doc['text']}")
    return '\n'.join(parts).strip()
