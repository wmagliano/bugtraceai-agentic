#!/usr/bin/env python3
"""BugTraceAI v3.0.2 cassette/RAG-aware operational TUI.

The TUI is a frontend only: it starts existing scripts and reads persisted state.
It does not interpret vulnerabilities or modify cognitive decisions.
"""
from __future__ import annotations
import json, os, signal, subprocess, sys
from pathlib import Path
from typing import Optional
from config_env import load_env, as_bool, as_int
load_env()

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import Button, Footer, Header, Label, ProgressBar, Static, Select, Log
    from textual.reactive import reactive
except ImportError:
    print("[ERROR] Falta Textual. Ejecute: ./install_tui.sh")
    raise SystemExit(2)

ROOT=Path(__file__).resolve().parent
KNOWLEDGE=ROOT/'data/knowledge.json'
RUN_LOG=ROOT/'logs/tui-runtime.log'
CONFIG_DIR=ROOT/'config'
CASSETTE_DIR=ROOT/'cassettes'
TERMINAL={'COMPLETED','INCONCLUSIVE','FAILED','SKIPPED'}

class BugTraceTUI(App):
    CSS='''
    Screen { layout: vertical; }
    #controls { height: 3; }
    #main { height: 1fr; }
    #summary { width: 2fr; border: round $accent; padding: 1; }
    #events { width: 3fr; border: round $primary; }
    Button { margin: 0 1; min-width: 12; }
    .metric { height: 1; }
    #active { height: 10; }
    #statusline { height: 2; padding: 0 1; }
    '''
    BINDINGS=[('q','quit','Salir'),('r','refresh_now','Actualizar'),('p','pause_resume','Pausar/Reanudar'),('s','stop_run','Detener')]
    process: Optional[subprocess.Popen]=None
    paused=False
    last_log_size=0

    def compose(self)->ComposeResult:
        configs=sorted(str(p.relative_to(ROOT)) for p in CONFIG_DIR.glob('*.json'))
        yield Header(show_clock=True)
        with Horizontal(id='controls'):
            yield Select([(c,c) for c in configs], value=configs[0] if configs else None, id='config')
            cassettes=sorted(p.name for p in CASSETTE_DIR.iterdir() if p.is_dir() and (p/'manifest.json').exists()) if CASSETTE_DIR.exists() else []
            yield Select([(c,c) for c in cassettes], value='dvwa-lab' if 'dvwa-lab' in cassettes else (cassettes[0] if cassettes else None), id='cassette')
            yield Button('Verificar',id='verify',variant='primary')
            yield Button('Resetear',id='reset',variant='warning')
            yield Button('Iniciar',id='start',variant='success')
            yield Button('Pausar',id='pause')
            yield Button('Detener',id='stop',variant='error')
            yield Button('Open Item',id='item')
            yield Button('Errors',id='errors')
        with Horizontal(id='main'):
            with Vertical(id='summary'):
                yield Label('Progress: 0 / 0',id='progress_label')
                yield ProgressBar(total=100,show_eta=False,id='progress')
                yield Static('Estado: IDLE',id='statusline')
                yield Static('Active: -\nURL: -\nState: -\nVulnerability: UNASSESSED\nExploitability: UNASSESSED\nAttempts: 0 / 4\nLast action: -\nLast result: -',id='active')
                yield Static('Loops: 0   LLM errors: 0   MCP: 0',id='metrics')
            yield Log(id='events',highlight=True,auto_scroll=True)
        yield Footer()

    def on_mount(self):
        RUN_LOG.parent.mkdir(parents=True,exist_ok=True)
        self.set_interval(1.0,self.refresh_state)
        self.refresh_state()
        missing=[name for name in ('run_v302_auto.sh','reset_v254_sessioncheck.sh','selftest_v302.py') if not (ROOT/name).exists()]
        if missing:
            self.query_one('#statusline',Static).update('Estado: PREFLIGHT ERROR')
            self.query_one('#events',Log).write_line('[red]Faltan archivos TUI: ' + ', '.join(missing) + '[/red]')
        else:
            self.query_one('#events',Log).write_line('[green]TUI v3.0.2 lista. Use Verificar antes de iniciar.[/green]')

    def selected_config(self):
        return str(self.query_one('#config',Select).value or 'config/dvwa.json')

    def selected_cassette(self):
        return str(self.query_one('#cassette',Select).value or 'dvwa-lab')

    def run_command(self,args:list[str],label:str,background=False,env=None):
        log=self.query_one('#events',Log)
        log.write_line(f'[bold]{label}[/bold]: {" ".join(args)}')
        if background:
            if self.process and self.process.poll() is None:
                log.write_line('[yellow]Ya existe una ejecución activa.[/yellow]'); return
            f=RUN_LOG.open('a',encoding='utf-8')
            child_env=os.environ.copy(); child_env.update(env or {})
            self.process=subprocess.Popen(args,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,text=True,start_new_session=True,env=child_env)
            self.paused=False
            self.query_one('#statusline',Static).update(f'Estado: RUNNING  PID: {self.process.pid}')
        else:
            result=subprocess.run(args,cwd=ROOT,capture_output=True,text=True)
            for line in (result.stdout+result.stderr).splitlines()[-30:]: log.write_line(line)
            log.write_line(f'[{"green" if result.returncode==0 else "red"}]returncode={result.returncode}[/]')

    async def on_button_pressed(self,event:Button.Pressed):
        bid=event.button.id
        cfg=self.selected_config()
        if bid=='verify': self.run_command(['python3','selftest_v302.py'],'Verificación v3.0.2')
        elif bid=='reset': self.run_command(['./reset_v254_sessioncheck.sh',cfg],'Reset')
        elif bid=='start':
            self.run_command(['./run_v302_auto.sh','500'],f'Inicio v3.0.2 cassette={self.selected_cassette()}',True,{'BUGTRACEAI_CONFIG':cfg,'BUGTRACEAI_CASSETTE':self.selected_cassette()})
        elif bid=='pause': self.action_pause_resume()
        elif bid=='stop': self.action_stop_run()
        elif bid=='item': self.show_active_item()
        elif bid=='errors': self.show_errors()

    def action_pause_resume(self):
        if not self.process or self.process.poll() is not None: return
        sig=signal.SIGCONT if self.paused else signal.SIGSTOP
        os.killpg(os.getpgid(self.process.pid),sig)
        self.paused=not self.paused
        self.query_one('#pause',Button).label='Reanudar' if self.paused else 'Pausar'
        self.query_one('#statusline',Static).update('Estado: PAUSED' if self.paused else 'Estado: RUNNING')

    def action_stop_run(self):
        if self.process and self.process.poll() is None:
            os.killpg(os.getpgid(self.process.pid),signal.SIGTERM)
            self.query_one('#statusline',Static).update('Estado: STOPPING')

    def action_refresh_now(self): self.refresh_state()

    def load_state(self):
        try: return json.loads(KNOWLEDGE.read_text(encoding='utf-8'))
        except Exception: return {}

    def active_item(self,k):
        aid=k.get('active_analysis_id')
        for item in k.get('analysis_queue') or []:
            if isinstance(item,dict) and item.get('analysis_id')==aid: return item
        active=k.get('active_resource'); url=active.get('resource') if isinstance(active,dict) else active
        for item in k.get('analysis_queue') or []:
            if isinstance(item,dict) and item.get('entry_url')==url: return item
        return None

    def refresh_state(self):
        k=self.load_state(); q=[x for x in k.get('analysis_queue') or [] if isinstance(x,dict)]
        closed=sum(1 for x in q if str(x.get('state','')).upper() in TERMINAL)
        total=len(q); pct=(closed/total*100) if total else 0
        self.query_one('#progress_label',Label).update(f'Progress: {closed} / {total}')
        bar=self.query_one('#progress',ProgressBar); bar.update(total=100,progress=pct)
        item=self.active_item(k)
        if item:
            a=item.get('attempt_state') or {}; actions=item.get('actions') or []; commands=item.get('commands') or []
            last_action=(actions[-1].get('action') if actions else '-')
            last_result=(commands[-1].get('returncode') if commands else '-')
            url=item.get('entry_url','-'); short=url.split('://',1)[-1]; short=short[short.find('/'):] if '/' in short else '/'
            v=(item.get('vulnerability_verdict') or {}).get('status','UNASSESSED'); v='INCONCLUSIVE' if str(v).upper()=='UNKNOWN' and str(item.get('state') or '').upper() not in {'NEW','MAPPED'} else ('UNASSESSED' if str(v).upper()=='UNKNOWN' else v); e=(item.get('exploitation') or {}).get('status','NOT_ATTEMPTED'); text=f"Active: {item.get('analysis_id','-')}\nURL: {short}\nState: {item.get('state','-')}\nVulnerability: {v}\nExploitability: {e}\nAttempts: {a.get('total_attempts',0)} / 4\nLast action: {last_action}\nLast result: {last_result}"
        else: text='Active: -\nURL: -\nState: -\nVulnerability: UNASSESSED\nExploitability: UNASSESSED\nAttempts: 0 / 4\nLast action: -\nLast result: -'
        self.query_one('#active',Static).update(text)
        loops=len((k.get('loop_guard') or {}).get('events') or [])
        llm=sum(int((v or {}).get('count',0)) for v in (k.get('llm_error_counters') or {}).values()) if isinstance(k.get('llm_error_counters'),dict) else 0
        mcp=sum(int((v or {}).get('mcp_executions',0)) for v in (k.get('autonomous_resource_counters') or {}).values())
        
        rag={}
        cog={}
        try: rag=json.loads((ROOT/'logs/v3/rag_statistics.json').read_text(encoding='utf-8'))
        except Exception: pass
        try: cog=json.loads((ROOT/'logs/v3/cognitive_progress.json').read_text(encoding='utf-8'))
        except Exception: pass
        version=os.getenv('BUGTRACEAI_VERSION','3.0.1c')
        rag_state='ON' if as_bool('BUGTRACEAI_RAG_ENABLED',True) else 'OFF'
        cache='HIT' if rag.get('cache_hit') else ('MISS' if rag else '-')
        learned='YES' if cog.get('learned_this_cycle') else ('NO' if cog else '-')
        self.query_one('#metrics',Static).update(f'Version: {version} | Cassette: {self.selected_cassette()} | Adaptive RAG: {rag_state} | Knowledge: {rag.get("selected_count",0)} docs | Prompt Tokens: {rag.get("prompt_tokens",0)} | Cache: {cache} | Cognitive: {learned} | Loops: {loops} | MCP: {mcp}')
        if self.process and self.process.poll() is not None:
            self.query_one('#statusline',Static).update(f'Estado: FINISHED ({self.process.returncode})')
        self.tail_log()

    def tail_log(self):
        if not RUN_LOG.exists(): return
        size=RUN_LOG.stat().st_size
        if size<self.last_log_size: self.last_log_size=0
        if size==self.last_log_size: return
        with RUN_LOG.open('r',encoding='utf-8',errors='replace') as f:
            f.seek(self.last_log_size); text=f.read(); self.last_log_size=f.tell()
        log=self.query_one('#events',Log)
        important=('SCHEDULER','AUTONOMOUS','LLM ACTION','BLOCKED','ERROR','LOOP','REPORT','DONE','MCP execution')
        for line in text.splitlines():
            if any(x in line for x in important): log.write_line(line[-220:])

    def show_active_item(self):
        item=self.active_item(self.load_state()); log=self.query_one('#events',Log)
        log.write_line(json.dumps(item or {'active':None},ensure_ascii=False,indent=2)[-8000:])

    def show_errors(self):
        k=self.load_state(); log=self.query_one('#events',Log)
        data={'llm_error_counters':k.get('llm_error_counters',{}),'recent_blocked_actions':k.get('recent_blocked_actions',[]),'navigation_failures':k.get('navigation_failures',{})}
        log.write_line(json.dumps(data,ensure_ascii=False,indent=2)[-8000:])

if __name__=='__main__': BugTraceTUI().run()
