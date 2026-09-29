#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from lifecycle_trace import emit
from cognitive_session import ensure_item_session, attach_command_result, apply_reflection, close_session
from url_blacklist import is_blacklisted_url, blacklist_reason
from black_vulns import is_black_vuln, black_vuln_reason
from capability_gate import normalize_capability_assessment, gate_exploitation_status, evaluate_architecture_validation, apply_vulnerability_first_hierarchy, derive_phase1_exploitation_status, should_terminalize_for_architecture
from semantic_claim_gate import normalize_hypothesis_type, can_confirm_vulnerability

TERMINAL_STATES={"COMPLETED","INCONCLUSIVE","FAILED","SKIPPED"}


def _v303i_apply_vulnerability_first(item):
    """Apply v3.0.3i downstream-state invariants to an Analysis Item in-place."""
    if not isinstance(item, dict):
        return item
    vv = item.get("vulnerability_verdict") or {}
    status = vv.get("status") if isinstance(vv, dict) else vv
    # Some paths persist assessment separately before vulnerability_verdict.
    if not status:
        status = item.get("assessment") or item.get("vulnerability_status")
    if not status:
        return item

    item["capability_assessment"] = apply_vulnerability_first_hierarchy(
        status, item.get("capability_assessment")
    )
    item["exploitation_status"] = derive_phase1_exploitation_status(status)
    # Preserve structured exploitation object when present.
    ex = item.get("exploitation")
    if isinstance(ex, dict):
        ex["status"] = item["exploitation_status"]
    return item

def utc_now(): return datetime.now(timezone.utc).isoformat()

def normalize_url(url: Any):
    if not isinstance(url,str) or not url.strip(): return None
    url=url.strip().split('#',1)[0]
    if not url.startswith(('http://','https://')): return url
    p=urlsplit(url); return urlunsplit((p.scheme.lower(),p.netloc.lower(),p.path or '/',p.query,''))

def _id_for(url:str, existing:list[dict[str,Any]]):
    used={x.get('analysis_id') for x in existing if isinstance(x,dict)}
    n=1
    while f'A-{n:04d}' in used: n+=1
    return f'A-{n:04d}'

def new_item(url:str, existing:list[dict[str,Any]], source='discovery'):
    now=utc_now()
    return {
      'analysis_id':_id_for(url,existing),'entry_url':url,'normalized_entry_url':url,
      'state':'NEW','priority':100000-len(existing),'created_at':now,'started_at':None,
      'updated_at':now,'finished_at':None,'observations':[],'hypotheses':[],
      'actions':[],'commands':[],'evidence':[],'state_history':[{
        'timestamp':now,'from':None,'to':'NEW','reason':'Analysis Item creado','source':source}],
      'discovered_urls':[],'capability_assessment':evaluate_architecture_validation(url),'finding_classification':{'type':'VULNERABILITY','summary':None},'vulnerability_verdict':{'status':'UNASSESSED','confidence':None,'summary':None,'evidence_ids':[],'decision_id':None,'updated_at':now},'exploitation':{'status':'NOT_ATTEMPTED','summary':None,'command_ids':[],'result_ids':[],'decision_id':None,'updated_at':now},'operator_assessment':None,'attempt_state':{'total_attempts':0,'consecutive_failures':0,
        'repeated_action_count':0,'last_action_fingerprint':None},'report':None,'closure':None,'cognitive_session':{'schema_version':'1.0','status':'OPEN','initial_observation':None,'active_hypothesis':None,'learned_facts':[],'cycles':[],'last_reflection':None,'summary':None,'updated_at':now}
    }

def ensure_schema(k:dict[str,Any], migrate_legacy=True):
    q=k.setdefault('analysis_queue',[])
    # v2.5.4-blacklist: administrative DVWA endpoints never become Analysis Items.
    q[:] = [item for item in q if not (isinstance(item,dict) and (is_blacklisted_url(item.get('entry_url') or item.get('normalized_entry_url')) or is_black_vuln(item.get('entry_url') or item.get('normalized_entry_url'))))]
    if not isinstance(q,list): q=[]; k['analysis_queue']=q
    k.setdefault('active_analysis_id',None)
    urls=[]
    for item in q:
        if not isinstance(item,dict): continue
        url=normalize_url(item.get('entry_url') or item.get('normalized_entry_url'))
        if not url: continue
        item['entry_url']=url; item['normalized_entry_url']=url
        item.setdefault('analysis_id',_id_for(url,q)); item.setdefault('state','NEW')
        for key in ('observations','hypotheses','actions','commands','evidence','state_history','discovered_urls'): item.setdefault(key,[])
        item.setdefault('attempt_state',{'total_attempts':0,'consecutive_failures':0,'repeated_action_count':0,'last_action_fingerprint':None})
        item.setdefault('report',None); item.setdefault('closure',None); item['capability_assessment']=evaluate_architecture_validation(url); ensure_item_session(item); item.setdefault('vulnerability_verdict',{'status':'UNASSESSED','confidence':None,'summary':None,'evidence_ids':[],'decision_id':None,'updated_at':utc_now()}); item.setdefault('exploitation',{'status':'NOT_ATTEMPTED','summary':None,'command_ids':[],'result_ids':[],'decision_id':None,'updated_at':utc_now()}); item.setdefault('operator_assessment',None); item.setdefault('created_at',utc_now()); item['updated_at']=item.get('updated_at') or utc_now()
        # v2.6.1a: migrate legacy UNKNOWN without asserting a security result.
        vv=item.get('vulnerability_verdict') or {}
        if str(vv.get('status') or '').upper()=='UNKNOWN':
            vv['status']='UNASSESSED'
            vv['source']=vv.get('source') or 'legacy_unknown_migration_v261a'
            item['vulnerability_verdict']=vv
        urls.append(url)
    if migrate_legacy:
        for raw in k.get('candidate_urls') or []:
            url=normalize_url(raw.get('url') if isinstance(raw,dict) else raw)
            if url and not is_blacklisted_url(url) and not is_black_vuln(url) and url not in urls: q.append(new_item(url,q,'legacy_migration')); urls.append(url)
    # candidate_urls queda como espejo de compatibilidad, no como cola autoritativa.
    k['candidate_urls']=[x['entry_url'] for x in q if isinstance(x,dict) and x.get('entry_url')]
    return k

def find_item(k:dict[str,Any], url=None, analysis_id=None):
    ensure_schema(k)
    n=normalize_url(url)
    for item in k['analysis_queue']:
        if analysis_id and item.get('analysis_id')==analysis_id: return item
        if n and item.get('normalized_entry_url')==n: return item
    return None

def add_item(k:dict[str,Any], url:str, source='discovery'):
    ensure_schema(k); url=normalize_url(url)
    if not url: return None,False
    if is_blacklisted_url(url):
        emit('BLACKLIST_SKIP',resource=url,component='analysis_queue',source=source,reason=blacklist_reason(url))
        print(f'[BLACKLIST_SKIP] URL administrativa DVWA excluida: {url}')
        return None,False
    if is_black_vuln(url):
        reason=black_vuln_reason(url)
        k.setdefault('black_vulns_skipped',[])
        if not any(isinstance(x,dict) and x.get('url')==url for x in k['black_vulns_skipped']):
            k['black_vulns_skipped'].append({'url':url,'reason':reason,'timestamp':utc_now(),'source':source})
        emit('BLACK_VULN_SKIP',resource=url,component='analysis_queue',source=source,reason=reason)
        print(f'[BLACK_VULN_SKIP] Recurso excluido por capability policy: {url}')
        return None,False
    old=find_item(k,url=url)
    if old: return old,False
    item=new_item(url,k['analysis_queue'],source); k['analysis_queue'].append(item); k['candidate_urls'].append(url)
    emit('CREATE',analysis_id=item.get('analysis_id'),resource=url,component='analysis_queue',source=source,state='NEW')
    return item,True

def set_state(k:dict[str,Any], url:str, state:str, reason:str, source='runtime'):
    item=find_item(k,url=url)
    if not item: item,_=add_item(k,url,source)
    if not item: return None
    prev=str(item.get('state') or 'NEW').upper(); state=str(state).upper()
    # R0-FINAL-C1-fix: terminal Analysis Items are monotonic during an autonomous run.
    # Only an explicit operator reopen may move them back to an active state.
    if prev in TERMINAL_STATES and state not in TERMINAL_STATES and source != 'operator_reopen':
        emit('TERMINAL_DOWNGRADE_BLOCKED',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue',from_state=prev,to_state=state,source=source)
        return item
    if prev!=state:
        item['state_history'].append({'timestamp':utc_now(),'from':prev,'to':state,'reason':reason,'source':source})
        emit('STATE_CHANGE',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue',from_state=prev,to_state=state,reason=reason,source=source)
    item['state']=state; item['updated_at']=utc_now()
    if item.get('started_at') is None and state not in {'NEW','QUEUED'}: item['started_at']=utc_now()
    if state in TERMINAL_STATES:
        item['finished_at']=utc_now(); item['closure']={'state':state,'reason':reason,'timestamp':utc_now(),'source':source}; close_session(item)
    return item

def set_active(k:dict[str,Any], url:str|None):
    ensure_schema(k)
    item=find_item(k,url=url) if url else None
    k['active_analysis_id']=item.get('analysis_id') if item else None

def active_item(k:dict[str,Any]): return find_item(k,analysis_id=k.get('active_analysis_id'))

def _append_unique(lst:list, obj:dict, key_fields:tuple[str,...]):
    sig=tuple(str(obj.get(x,'')) for x in key_fields)
    if any(tuple(str(y.get(x,'')) for x in key_fields)==sig for y in lst if isinstance(y,dict)): return
    lst.append(obj)

def command_execution_status(x:dict[str,Any])->str:
    explicit=str(x.get('execution_status') or '').upper().strip()
    if explicit: return explicit
    if x.get('blocked'): return 'BLOCKED'
    if x.get('timeout') or x.get('timed_out'): return 'TIMEOUT'
    if x.get('cancelled'): return 'CANCELLED'
    executed=x.get('executed', True)
    if not executed: return 'NOT_EXECUTED'
    rc=x.get('returncode')
    if rc is None: return 'UNKNOWN_RESULT'
    return 'SUCCEEDED' if x.get('ok') is True or rc == 0 else 'FAILED'

def sync_runtime(k:dict[str,Any]):
    ensure_schema(k)
    active=k.get('active_resource'); active_url=active.get('resource') if isinstance(active,dict) else active
    if active_url: set_active(k,active_url)
    # estados legacy -> expediente
    for url,st in (k.get('resource_state') or {}).items():
        state=st.get('state') if isinstance(st,dict) else st
        if state: set_state(k,url,state,(st.get('reason') if isinstance(st,dict) else '') or 'Sincronización runtime','legacy_runtime')
    # memoria cognitiva -> expediente
    for x in k.get('cognitive_knowledge') or []:
        if not isinstance(x,dict): continue
        item=find_item(k,url=x.get('resource'))
        if not item: continue
        kind=str(x.get('kind') or '').lower(); base={'timestamp':x.get('timestamp') or utc_now(),'decision_id':x.get('decision_id'),'text':x.get('text'),'confidence':x.get('confidence'),'status':x.get('status')}
        target=item['hypotheses'] if kind.startswith('hypoth') else item['evidence'] if kind in {'evidence','verdict','verdicts'} else item['observations']
        _append_unique(target,base,('decision_id','text'))
    for x in k.get('mcp_command_observations') or []:
        if not isinstance(x,dict): continue
        item=find_item(k,url=x.get('resource'))
        if not item: continue
        stdout=x.get('stdout_preview') or ''
        stderr=x.get('stderr_preview') or ''
        cmd={'command_id':x.get('command_id') or f"CMD-{len(item['commands'])+1:04d}",'timestamp':x.get('timestamp') or utc_now(),'decision_id':x.get('decision_id'),'requested_by':'LLM','action':x.get('source_action') or 'propose_mcp_command','command':x.get('command'),'tested_url':x.get('tested_url'),'reason':x.get('reason'),'risk_level':x.get('risk_level'),'approved':x.get('approved',True),'executed':x.get('executed',True),'ok':x.get('ok'),'returncode':x.get('returncode'),'stdout_preview':stdout,'stderr_preview':stderr,'stdout_sha256':x.get('stdout_sha256') or hashlib.sha256(stdout.encode('utf-8','replace')).hexdigest(),'stderr_sha256':x.get('stderr_sha256') or hashlib.sha256(stderr.encode('utf-8','replace')).hexdigest(),'evidence_hint':x.get('evidence_hint'),'verified_evidence':x.get('verified_evidence') or [],'expected_evidence':x.get('expected_evidence'),'predicate_result':x.get('predicate_result'),'execution_status':command_execution_status(x)}
        before=len(item['commands']); _append_unique(item['commands'],cmd,('decision_id','command'))
        if len(item['commands'])>before: emit('ADD_COMMAND',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue.sync_runtime',command_id=cmd.get('command_id'),decision_id=cmd.get('decision_id'),execution_status=cmd.get('execution_status'))
        if len(item['commands'])>before: attach_command_result(item, cmd)
        verified = x.get('verified_evidence') or []
        if verified:
            for finding in verified:
                ev={'evidence_id':f"EVID-{len(item['evidence'])+1:04d}",'timestamp':x.get('timestamp') or utc_now(),'decision_id':x.get('decision_id'),'text':str(finding.get('text') or finding),'excerpt':finding.get('excerpt') if isinstance(finding,dict) else None,'kind':finding.get('kind') if isinstance(finding,dict) else None,'confidence':'high','source':'mcp_result_verified','command_id':cmd.get('command_id'),'tested_url':x.get('tested_url'),'stdout_sha256':cmd.get('stdout_sha256')}
                before_ev=len(item['evidence']); _append_unique(item['evidence'],ev,('decision_id','text','tested_url'))
                if len(item['evidence'])>before_ev: emit('ADD_EVIDENCE',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue.sync_runtime',evidence_id=ev.get('evidence_id'),decision_id=ev.get('decision_id'),source=ev.get('source'))
        else:
            # Compatibilidad con observaciones antiguas. No crea evidencia nueva a
            # partir de hints legacy no verificados.
            pass
        act={'timestamp':x.get('timestamp') or utc_now(),'decision_id':x.get('decision_id'),'action':x.get('source_action') or 'propose_mcp_command','reason':x.get('reason'),'status':'EXECUTED'}
        _append_unique(item['actions'],act,('decision_id','action','reason'))
        item['attempt_state']['total_attempts']=len(item['commands'])
    return k

VERDICT_STATUSES={'UNASSESSED','CONFIRMED','NOT_CONFIRMED','INCONCLUSIVE','NO_FINDING'}
EXPLOIT_STATUSES={'CONFIRMED','LIMITED','NOT_CONFIRMED','NOT_TESTABLE','NOT_APPLICABLE','NOT_ATTEMPTED','ATTEMPTED','PARTIAL','FAILED','INCOMPLETE'}
CONFIDENCE_VALUES={'LOW','MEDIUM','HIGH'}

def finalize_runtime_assessment(k:dict[str,Any], resource:str, terminal_state:str, reason:str, decision_id:str|None=None)->dict|None:
    """Close the assessment layer when runtime terminates an Analysis Item.

    This function does not infer a vulnerability class or reinterpret command
    output. It only prevents an operational terminal state from leaving the
    scientific verdict undefined. Explicit LLM assessments always win.
    """
    ensure_schema(k)
    item=find_item(k,url=resource)
    if not item:
        return None
    now=utc_now()
    terminal_state=str(terminal_state or 'INCONCLUSIVE').upper().strip()
    verdict=item.get('vulnerability_verdict') or {}
    if str(verdict.get('status') or 'UNASSESSED').upper() in {'UNKNOWN','UNASSESSED'}:
        status='INCONCLUSIVE'  # v2.6.0c: un cierre operativo nunca demuestra ausencia de hallazgo
        item['vulnerability_verdict']={
            'status':status,
            'confidence':None,
            'summary':reason,
            'evidence_ids':[str(x.get('evidence_id')) for x in (item.get('evidence') or []) if isinstance(x,dict) and x.get('evidence_id')],
            'decision_id':decision_id,
            'updated_at':now,
            'source':'runtime_terminal_guard',
        }
    exploitation=item.get('exploitation') or {}
    if str(exploitation.get('status') or 'NOT_ATTEMPTED').upper() == 'NOT_ATTEMPTED':
        commands=item.get('commands') or []
        attempted=any(str((x or {}).get('execution_status') or '').upper() in {'SUCCEEDED','FAILED','TIMEOUT','UNKNOWN_RESULT'} for x in commands if isinstance(x,dict))
        item['exploitation']={
            'status':'NOT_CONFIRMED' if attempted else ('NOT_APPLICABLE' if str((item.get('vulnerability_verdict') or {}).get('status') or '').upper() != 'CONFIRMED' else 'NOT_CONFIRMED'),
            'summary':('Hubo ejecución técnica, pero la explotación no quedó confirmada antes del cierre: ' + reason) if attempted else (('La explotación no se evaluó porque la vulnerabilidad no quedó confirmada: ' + reason) if str((item.get('vulnerability_verdict') or {}).get('status') or '').upper() != 'CONFIRMED' else ('Vulnerabilidad confirmada; explotación no demostrada antes del cierre: ' + reason)),
            'command_ids':[str(x.get('command_id')) for x in commands if isinstance(x,dict) and x.get('command_id')],
            'result_ids':[],
            'decision_id':decision_id,
            'updated_at':now,
            'source':'runtime_terminal_guard',
        }
    item['updated_at']=now
    return item

def apply_llm_assessment(k:dict[str,Any], decision:dict[str,Any], resource:str|None=None)->dict|None:
    """Persist the LLM's explicit assessment without inferring vulnerability semantics."""
    ensure_schema(k)
    item=find_item(k,url=resource) if resource else active_item(k)
    if not item:
        active=k.get('active_resource')
        active_url=active.get('resource') if isinstance(active,dict) else active
        item=find_item(k,url=active_url)
    if not item: return None
    now=utc_now(); decision_id=decision.get('decision_id')
    raw_reflection=decision.get('reflection')
    if isinstance(raw_reflection,dict):
        normalized_reflection = apply_reflection(item, raw_reflection, decision_id)
        session = item.get("cognitive_session") or {}
        latest_cycle = next((c for c in reversed(session.get("cycles") or []) if c.get("reflection",{}).get("decision_id") == decision_id), None)
        predicate = ((latest_cycle or {}).get("result") or {}).get("predicate_result") or {}
        if normalized_reflection.get("evidence_candidate") and predicate.get("evaluated") is True and predicate.get("matched") is True:
            ev={
                "evidence_id":f"EVID-{len(item.get('evidence') or [])+1:04d}",
                "timestamp":now,
                "decision_id":decision_id,
                "text":normalized_reflection.get("evidence_reason") or predicate.get("meaning") or normalized_reflection.get("interpretation"),
                "excerpt":predicate.get("excerpt"),
                "kind":"llm_promoted_predicate",
                "confidence":str(normalized_reflection.get("confidence") or "MEDIUM").lower(),
                "source":"llm_evidence_promotion",
                "command_id":(latest_cycle or {}).get("command_id"),
                "predicate":predicate,
            }
            before_ev=len(item.get("evidence") or [])
            _append_unique(item.setdefault("evidence",[]),ev,("decision_id","text","command_id"))
            if len(item["evidence"])>before_ev:
                emit("ADD_EVIDENCE",analysis_id=item.get("analysis_id"),resource=item.get("entry_url"),component="analysis_queue.apply_llm_assessment",evidence_id=ev.get("evidence_id"),decision_id=decision_id,source=ev.get("source"))
                if item.get("state") not in {"CONFIRMED","COMPLETED","INCONCLUSIVE"}:
                    item["state"]="EVIDENCE_COLLECTED"
        assessment=str(normalized_reflection.get("assessment") or "CONTINUE").upper()
        if assessment in {"CONFIRMED","NOT_CONFIRMED","INCONCLUSIVE","NO_FINDING"}:
            promoted_ids=[str(x.get("evidence_id")) for x in item.get("evidence") or [] if isinstance(x,dict) and x.get("evidence_id")]
            # v3.0.2 semantic guard: CONFIRMED must be structurally consistent
            # with the reflection and backed by persisted evidence. A refuted/
            # weakened/not-evaluated hypothesis cannot become CONFIRMED.
            effect=str(normalized_reflection.get("hypothesis_effect") or "NOT_EVALUATED").upper()
            evidence_candidate=bool(normalized_reflection.get("evidence_candidate"))
            hypothesis_type=normalize_hypothesis_type(normalized_reflection.get("hypothesis_type"))
            if assessment=="CONFIRMED" and not can_confirm_vulnerability(hypothesis_type):
                emit("SEMANTIC_CLAIM_GATE_REJECTED",analysis_id=item.get("analysis_id"),resource=item.get("entry_url"),component="analysis_queue.apply_llm_assessment",decision_id=decision_id,hypothesis_type=hypothesis_type,hypothesis_effect=effect,reason="non_vulnerability_claim_cannot_confirm_vulnerability")
                assessment="INCONCLUSIVE"
            if assessment=="CONFIRMED" and (effect != "SUPPORTED" or not evidence_candidate or not promoted_ids):
                emit("SEMANTIC_CONFIRMATION_REJECTED",analysis_id=item.get("analysis_id"),resource=item.get("entry_url"),component="analysis_queue.apply_llm_assessment",decision_id=decision_id,hypothesis_type=hypothesis_type,hypothesis_effect=effect,evidence_candidate=evidence_candidate,evidence_count=len(promoted_ids))
                assessment="INCONCLUSIVE"
            item["vulnerability_verdict"]={
                "status":assessment,
                "confidence":str(normalized_reflection.get("confidence") or "MEDIUM").upper(),
                "summary":normalized_reflection.get("interpretation"),
                "evidence_ids":promoted_ids,
                "decision_id":decision_id,
                "updated_at":now,
                "source":"llm_reflection_assessment",
            }
            if assessment=="CONFIRMED": item["state"]="CONFIRMED"
    raw_v=decision.get('vulnerability_verdict')
    if isinstance(raw_v,dict):
        status=str(raw_v.get('status') or 'UNASSESSED').upper().strip()
        if status in VERDICT_STATUSES:
            confidence=str(raw_v.get('confidence') or '').upper().strip() or None
            if confidence not in CONFIDENCE_VALUES: confidence=None
            evidence_ids=[str(x) for x in (raw_v.get('evidence_ids') or []) if x]
            if status=='CONFIRMED':
                # v3.0.3d semantic consistency gate: raw vulnerability_verdict must
                # not bypass the stronger reflection assessment. Persisted evidence
                # alone proves that something was observed, not that the active
                # security hypothesis was demonstrated.
                ref = normalized_reflection if isinstance(normalized_reflection, dict) else {}
                ref_assessment = str(ref.get('assessment') or 'CONTINUE').upper()
                ref_effect = str(ref.get('hypothesis_effect') or 'NOT_EVALUATED').upper()
                ref_type = normalize_hypothesis_type(ref.get('hypothesis_type'))
                ref_candidate = bool(ref.get('evidence_candidate'))
                has_evidence = bool(evidence_ids or (item.get('evidence') or []))
                if (ref_assessment != 'CONFIRMED' or not can_confirm_vulnerability(ref_type) or ref_effect != 'SUPPORTED' or not ref_candidate or not has_evidence):
                    emit('SEMANTIC_CONFIRMATION_REJECTED',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue.raw_verdict_guard_v304',decision_id=decision_id,reason='raw_confirmed_not_supported_by_reflection',reflection_assessment=ref_assessment,hypothesis_type=ref_type,hypothesis_effect=ref_effect,evidence_candidate=ref_candidate,has_evidence=has_evidence)
                    status='INCONCLUSIVE'
            item['vulnerability_verdict']={
                'status':status,'confidence':confidence,'summary':raw_v.get('summary'),
                'evidence_ids':evidence_ids,'decision_id':decision_id,'updated_at':now,
            }
    # v3.0.3h: architectural capability is authoritative and independent of LLM output.
    # Re-evaluate every decision so stale/default values can never silently become FULL.
    item['capability_assessment']=evaluate_architecture_validation(item.get('entry_url'))
    item['capability_assessment']['decision_id']=decision_id
    item['capability_assessment']['updated_at']=now
    raw_fc=decision.get('finding_classification')
    if isinstance(raw_fc,dict):
        ftype=str(raw_fc.get('type') or 'VULNERABILITY').upper().strip()
        if ftype in {'VULNERABILITY','DISCLOSURE','MISCONFIGURATION','EXPOSURE','INFORMATIONAL'}:
            item['finding_classification']={'type':ftype,'summary':raw_fc.get('summary'),'decision_id':decision_id,'updated_at':now}
    raw_e=decision.get('exploitation')
    if isinstance(raw_e,dict):
        status=str(raw_e.get('status') or 'NOT_CONFIRMED').upper().strip()
        status={'PARTIAL':'LIMITED','ATTEMPTED':'NOT_CONFIRMED','FAILED':'NOT_CONFIRMED','INCOMPLETE':'NOT_CONFIRMED','NOT_ATTEMPTED':'NOT_CONFIRMED'}.get(status,status)
        vuln_status=str((item.get('vulnerability_verdict') or {}).get('status') or 'UNASSESSED').upper()
        capability=evaluate_architecture_validation(item.get('entry_url'))
        item['capability_assessment']=capability
        requested=status
        status,gate_reason=gate_exploitation_status(vuln_status,status,capability)
        if gate_reason:
            emit('CAPABILITY_GATE_APPLIED',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='analysis_queue.apply_llm_assessment',decision_id=decision_id,vulnerability_status=vuln_status,requested_exploitation_status=requested,final_exploitation_status=status,gate_reason=gate_reason,unavailable_capabilities=capability.get('unavailable_capabilities'))
        if status in EXPLOIT_STATUSES:
            summary=raw_e.get('summary')
            if gate_reason in {'required_runtime_capability_unavailable','architectural_runtime_validation_unavailable'}:
                summary=(summary or 'Explotación no observable con la arquitectura actual.') + ' Requiere validación especializada: ' + ', '.join(capability.get('unavailable_capabilities') or [])
            item['exploitation']={
                'status':status,'summary':summary,
                'command_ids':[str(x) for x in (raw_e.get('command_ids') or []) if x],
                'result_ids':[str(x) for x in (raw_e.get('result_ids') or []) if x],
                'decision_id':decision_id,'updated_at':now,
            }
            if vuln_status == 'CONFIRMED' and status == 'CONFIRMED':
                item['state']='EXPLOITABLE'
    # v3.0.4 also activates the vulnerability-first hierarchy introduced in v3.0.3i.
    # NO_FINDING short-circuits downstream capability/exploitation semantics; CONFIRMED
    # retains the architecture-owned capability result; INCONCLUSIVE remains conservative.
    _v303i_apply_vulnerability_first(item)
    item['updated_at']=now
    return item
