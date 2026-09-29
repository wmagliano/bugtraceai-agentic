#!/usr/bin/env python3
"""Web target URL blacklist. Config-driven with DVWA-compatible fallback."""
from __future__ import annotations
import json, os
from typing import Any
from urllib.parse import urlsplit
DEFAULT_PATHS=("/setup.php","/login.php","/logout.php","/security.php")
def _paths():
    raw=os.environ.get("BUGTRACEAI_URL_BLACKLIST_JSON","")
    try: vals=json.loads(raw) if raw else list(DEFAULT_PATHS)
    except Exception: vals=list(DEFAULT_PATHS)
    return frozenset(normalized_path(x) for x in vals if normalized_path(x))
def normalized_path(url:Any)->str:
    if not isinstance(url,str) or not url.strip(): return ""
    try: path=urlsplit(url.strip()).path or "/"
    except Exception: return ""
    if not path.startswith("/"): path="/"+path
    return path.rstrip("/").lower() or "/"
def is_blacklisted_url(url:Any)->bool: return normalized_path(url) in _paths()
def blacklist_reason(url:Any)->str|None:
    path=normalized_path(url)
    return f"site_excluded_endpoint:{path}" if path in _paths() else None
