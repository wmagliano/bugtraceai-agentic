#!/usr/bin/env python3
from __future__ import annotations
import os
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parent

def load_env(path: str|Path|None=None, *, override: bool=False)->dict[str,str]:
    p=Path(path or os.getenv('BUGTRACEAI_ENV_FILE') or ROOT/'config.env')
    values:dict[str,str]={}
    if not p.exists(): return values
    for raw in p.read_text(encoding='utf-8').splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        key,val=line.split('=',1); key=key.strip(); val=val.strip().strip('"').strip("'")
        values[key]=val
        if override or key not in os.environ: os.environ[key]=val
    return values

def as_bool(name:str, default:bool=False)->bool:
    return os.getenv(name,'1' if default else '0').strip().lower() in {'1','true','yes','on','si','sí'}

def as_int(name:str, default:int)->int:
    try: return int(os.getenv(name,str(default)).strip())
    except Exception: return default

load_env()
