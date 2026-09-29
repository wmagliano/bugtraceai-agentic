#!/usr/bin/env python3
import json, os, tempfile
from pathlib import Path
from analysis_queue import new_item, ensure_schema, set_state, add_item
from resource_scheduler import ResourceScheduler

os.environ['BUGTRACEAI_MAX_RESOURCE_ITERATIONS']='20'

# 1. Absolute Analysis Item/resource budget.
with tempfile.TemporaryDirectory() as td:
    p=Path(td)/'knowledge.json'; url='http://lab.local/test'
    item=new_item(url, [], 'selftest')
    p.write_text(json.dumps({'analysis_queue':[item],'candidate_urls':[url],
        'visited_urls':[url],'completed_urls':[],
        'resource_state':{url:{'state':'MAPPED'}},'active_resource':None,'scheduler':{}}))
    for n in range(1,20):
        sel=ResourceScheduler(p).select(); assert sel and sel.resource==url, (n,sel)
    assert ResourceScheduler(p).select() is None
    s=ResourceScheduler(p); q=s.queue()[url]
    ai=next(x for x in s.k['analysis_queue'] if x['entry_url']==url)
    assert q['state']=='INCONCLUSIVE'
    assert ai['state']=='INCONCLUSIVE'
    assert ai['resource_iteration_count']==20
    assert s.active() is None

# 2. Baseline same-action hard guard remains 10 and persists closure.
with tempfile.TemporaryDirectory() as td:
    p=Path(td)/'knowledge.json'; url='http://lab.local/loop'
    item=new_item(url, [], 'selftest')
    p.write_text(json.dumps({'analysis_queue':[item],'candidate_urls':[url],
        'visited_urls':[url],'completed_urls':[],
        'resource_state':{url:{'state':'MAPPED'}},'active_resource':None,'scheduler':{}}))
    count=0
    for _ in range(10): count=ResourceScheduler(p).register_action(url,'propose_command','same')
    s=ResourceScheduler(p)
    assert count==10
    assert s.queue()[url]['state']=='INCONCLUSIVE'
    assert next(x for x in s.k['analysis_queue'] if x['entry_url']==url)['state']=='INCONCLUSIVE'

# 3. Terminal state is monotonic except explicit operator reopen.
k={'analysis_queue':[],'candidate_urls':[]}; ensure_schema(k)
url='http://lab.local/terminal'; item,_=add_item(k,url,'selftest')
set_state(k,url,'COMPLETED','done','selftest')
set_state(k,url,'MAPPED','bad downgrade','legacy_runtime')
assert item['state']=='COMPLETED'
set_state(k,url,'NEW','manual reopen','operator_reopen')
assert item['state']=='NEW'

print('R0-FINAL-C1-fix selftest: OK')
