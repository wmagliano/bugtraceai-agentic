#!/usr/bin/env python3
"""Web vulnerability-family deferral policy. Config-driven with R0 DVWA fallback."""
from __future__ import annotations
import json, os
from typing import Any
from urllib.parse import urlsplit
DEFAULT_PATHS={"/vulnerabilities/weak_id/":"weak_session_ids","/vulnerabilities/captcha/":"captcha"}
def normalized_path(url:Any)->str:
    if not isinstance(url,str) or not url.strip(): return ""
    try: path=urlsplit(url.strip()).path or "/"
    except Exception: return ""
    if not path.startswith("/"): path="/"+path
    path=path.lower()
    if not path.endswith("/"): path+="/"
    return path
def _paths():
    raw=os.environ.get("BUGTRACEAI_VULN_BLACKLIST_JSON","")
    try: vals=json.loads(raw) if raw else DEFAULT_PATHS
    except Exception: vals=DEFAULT_PATHS
    if isinstance(vals,list): vals={x:x for x in vals}
    return {normalized_path(k):str(v) for k,v in vals.items() if normalized_path(k)}
def black_vuln_name(url:Any)->str|None: return _paths().get(normalized_path(url))
def is_black_vuln(url:Any)->bool: return black_vuln_name(url) is not None
def black_vuln_reason(url:Any)->str|None:
    name=black_vuln_name(url); return f"capability_policy_deferred:{name}" if name else None
