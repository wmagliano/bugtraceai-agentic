#!/usr/bin/env python3
"""BugTraceAI v3.0.1f-r4: DVWA session/security integrity guard.

Runs outside the LLM. It checks the Kali-resident cookie against a neutral
vulnerability page and reads the effective security level from the DVWA footer.
It requires an authenticated session and the configured security level, and uses
the trusted DVWA login wrapper to recover the laboratory state.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "data" / "session_guard.json"
DEFAULT_CONFIG = ROOT / "config" / "dvwa.json"
COOKIE_JAR = "/tmp/bugtraceai-session/dvwa_cookie.txt"
LOGIN_WRAPPER = "bugtraceai_dvwa_login"
SESSION_GUARD_VERSION = "3.0.1f-r4"
RESET_ATTEMPTS = 2
OPERATOR_RECOVERY_ATTEMPTS = 3


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def mcp_exec(mcp_base: str, command: str, timeout: int = 60) -> dict[str, Any]:
    payload = json.dumps({"command": command, "timeout": timeout}).encode()
    req = urllib.request.Request(
        mcp_base.rstrip("/") + "/tools/exec",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout + 10) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def parse_effective_page(html: str) -> dict[str, Any]:
    text = html or ""
    low = text.lower()
    login_markers = (
        "<title>login", "user login", "name=\"username\"", "name='username'",
        "login.php", "dvwa login",
    )
    authenticated = not any(marker in low for marker in login_markers)

    level = None
    # 1) security.php selector. Accept attributes in any order and both quote styles.
    option_patterns = [
        r'<option\b(?=[^>]*\bselected(?:\s*=\s*[\"\'][^\"\']*[\"\'])?)(?=[^>]*\bvalue\s*=\s*[\"\'](low|medium|high|impossible)[\"\'])[^>]*>',
        r'<option\b(?=[^>]*\bvalue\s*=\s*[\"\'](low|medium|high|impossible)[\"\'])(?=[^>]*\bselected(?:\s*=\s*[\"\'][^\"\']*[\"\'])?)[^>]*>',
    ]
    for pattern in option_patterns:
        match = re.search(pattern, text, flags=re.I | re.S)
        if match:
            level = match.group(1).lower()
            break

    # 2) Effective level displayed in DVWA pages/footer.
    if level is None:
        patterns = [
            r'<em>\s*Security\s+Level:\s*</em>\s*(?:<[^>]+>\s*)*(low|medium|high|impossible)',
            r'Security\s+Level:\s*(?:</?[^>]*>\s*)*(low|medium|high|impossible)',
            r'current\s+security\s+level[^a-z]+(low|medium|high|impossible)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.I | re.S)
            if match:
                level = match.group(1).lower()
                break

    # DVWA commonly persists this value in the PHPSESSID-backed security cookie.
    # A successful security.php response without a selected option is not enough.
    return {"authenticated": authenticated, "security": level}


def check_once(cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    target = cfg["target"]["base_url"].rstrip("/")
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = cfg.get("authentication", {}).get("cookie_jar") or COOKIE_JAR
    command = " ".join(shlex.quote(x) for x in [
        "curl", "-ksS", "-L", "-m", "20", "-b", cookie,
        target + "/vulnerabilities/sqli/",
    ])
    result = mcp_exec(mcp, command, timeout=30)
    html = result.get("stdout", "") or ""
    parsed = parse_effective_page(html)
    parsed.update({
        "ok": bool(result.get("ok")) and result.get("returncode") == 0,
        "returncode": result.get("returncode"),
        "stderr_preview": (result.get("stderr") or "")[-500:],
    })
    return parsed, result


def recover(cfg: dict[str, Any]) -> dict[str, Any]:
    auth = cfg.get("authentication", {})
    target = cfg["target"]["base_url"].rstrip("/")
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = auth.get("cookie_jar") or COOKIE_JAR
    desired = auth.get("security") or "low"
    command = " ".join(shlex.quote(str(x)) for x in [
        LOGIN_WRAPPER,
        target,
        auth.get("username") or "admin",
        auth.get("password") or "password",
        desired,
        cookie,
    ])
    return mcp_exec(mcp, command, timeout=120)


def classify_failure(result: dict[str, Any] | None, exc: Exception | None = None) -> str:
    """Classify operational failures without affecting cognitive decisions."""
    if exc is not None:
        text = str(exc).lower()
        if "timed out" in text or "timeout" in text:
            return "timeout"
        if "no route to host" in text:
            return "no_route_to_host"
        if "connection refused" in text:
            return "connection_refused"
        return "transport_error"
    result = result or {}
    text = ((result.get("stdout") or "") + "\n" + (result.get("stderr") or "")).lower()
    if "no route to host" in text:
        return "no_route_to_host"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "login no confirmado" in text or "página de login" in text or "login.php" in text:
        return "credentials_or_session_invalid"
    if not result.get("ok") or result.get("returncode") not in (0, None):
        return "mcp_command_failed"
    return "verification_failed"


def bootstrap_cookie(cfg: dict[str, Any]) -> dict[str, Any]:
    """Replace the stale cookie jar with a fresh anonymous DVWA session."""
    auth = cfg.get("authentication", {})
    target = cfg["target"]["base_url"].rstrip("/")
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = auth.get("cookie_jar") or COOKIE_JAR
    command = " ".join(shlex.quote(str(x)) for x in [
        "curl", "-ksS", "-L", "-m", "20", "-c", cookie,
        target + "/login.php",
    ])
    return mcp_exec(mcp, command, timeout=30)


def read_cookie_security(cfg: dict[str, Any]) -> str | None:
    """Read only the DVWA security cookie value from Kali, never the session id."""
    auth = cfg.get("authentication", {})
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = auth.get("cookie_jar") or COOKIE_JAR
    command = " ".join(shlex.quote(str(x)) for x in [
        "grep", "-i", "security", cookie,
    ])
    try:
        result = mcp_exec(mcp, command, timeout=20)
    except Exception:
        return None
    text = result.get("stdout") or ""
    values = re.findall(r"(?:^|\s)security\s+(low|medium|high|impossible)\s*$",
                        text, flags=re.I | re.M)
    return values[-1].lower() if values else None


def clear_cookie_jar(cfg: dict[str, Any]) -> dict[str, Any]:
    """Truncate the Kali cookie jar through the MCP safe redirect policy."""
    auth = cfg.get("authentication", {})
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = auth.get("cookie_jar") or COOKIE_JAR
    command = "printf '' > " + shlex.quote(str(cookie))
    return mcp_exec(mcp, command, timeout=20)


def operator_recovery_enabled() -> bool:
    value = os.environ.get("BUGTRACEAI_OPERATOR_SESSION_RECOVERY", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _operator_key(attempt: int, total: int) -> str | None:
    print()
    print("=" * 60)
    print("[SESSION GUARD] OPERATOR RECOVERY REQUIRED")
    print("=" * 60)
    print("No fue posible confirmar una sesión DVWA válida.")
    print()
    print("Cookie detectada:")
    print("  security=impossible")
    print()
    print("Acción requerida:")
    print()
    print("1) Abra DVWA")
    print("2) Ingrese a /setup.php")
    print('3) Presione "Create / Reset Database"')
    print("4) Espere a que DVWA finalice")
    print("5) Regrese a esta consola")
    print("6) Presione R para continuar")
    print()
    print("[R] Reintentar recuperación de sesión")
    print("[Q] Guardar estado y salir")
    print()
    print(f"Intento manual: {attempt}/{total}")
    print("=" * 60)

    if not sys.stdin or not sys.stdin.isatty():
        print("[SESSION GUARD] Entrada interactiva no disponible; guardando estado y saliendo.")
        return None

    while True:
        try:
            key = input("Seleccione R o Q: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if key in {"R", "Q"}:
            return key
        print("[SESSION GUARD] Opción inválida. Presione R para reintentar o Q para salir.")


def operator_reset_and_recover(
    cfg: dict[str, Any],
    history: list[dict[str, Any]],
    *,
    analysis_id: str | None,
) -> tuple[bool, str]:
    """Pause for an operator reset, then retry the same session up to three times."""
    if not operator_recovery_enabled():
        history.append({
            "timestamp": now(), "phase": "operator_recovery",
            "event": "operator_recovery_disabled", "analysis_id": analysis_id,
            "ok": False,
        })
        return False, "disabled"

    cookie_security = read_cookie_security(cfg)
    if cookie_security is None:
        try:
            status, _ = check_once(cfg)
            cookie_security = status.get("security")
        except Exception:
            cookie_security = None

    if cookie_security != "impossible":
        history.append({
            "timestamp": now(), "phase": "operator_recovery",
            "event": "operator_recovery_not_applicable",
            "analysis_id": analysis_id, "ok": False,
            "cookie_security": cookie_security,
        })
        return False, "not_applicable"

    history.append({
        "timestamp": now(), "phase": "operator_recovery",
        "event": "operator_recovery_requested", "analysis_id": analysis_id,
        "ok": False, "cookie_security": "impossible",
    })

    total = int(os.environ.get(
        "BUGTRACEAI_OPERATOR_RECOVERY_ATTEMPTS",
        str(OPERATOR_RECOVERY_ATTEMPTS),
    ))
    total = max(1, min(total, OPERATOR_RECOVERY_ATTEMPTS))

    for attempt in range(1, total + 1):
        key = _operator_key(attempt, total)
        if key != "R":
            event = "operator_recovery_aborted" if key == "Q" else "operator_recovery_unavailable"
            history.append({
                "timestamp": now(), "phase": "operator_recovery",
                "event": event, "attempt": attempt,
                "analysis_id": analysis_id, "ok": False,
            })
            return False, "aborted" if key == "Q" else "unavailable"

        print("[SESSION GUARD] Limpiando cookie anterior")
        history.append({
            "timestamp": now(), "phase": "operator_recovery",
            "event": "operator_recovery_attempt", "attempt": attempt,
            "analysis_id": analysis_id, "ok": False,
        })

        try:
            cleared = clear_cookie_jar(cfg)
            clear_ok = bool(cleared.get("ok")) and cleared.get("returncode") == 0
            history.append({
                "timestamp": now(), "phase": "operator_cookie_clear",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": clear_ok,
                "failure_class": None if clear_ok else classify_failure(cleared),
                "returncode": cleared.get("returncode"),
                "stderr_preview": (cleared.get("stderr") or "")[-500:],
            })
        except Exception as exc:
            clear_ok = False
            history.append({
                "timestamp": now(), "phase": "operator_cookie_clear",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": False, "failure_class": classify_failure(None, exc),
                "error": str(exc),
            })

        print("[SESSION GUARD] Creando cookie nueva")
        try:
            fresh = bootstrap_cookie(cfg)
            fresh_ok = bool(fresh.get("ok")) and fresh.get("returncode") == 0
            history.append({
                "timestamp": now(), "phase": "operator_cookie_bootstrap",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": fresh_ok,
                "failure_class": None if fresh_ok else classify_failure(fresh),
                "returncode": fresh.get("returncode"),
                "stderr_preview": (fresh.get("stderr") or "")[-500:],
            })
        except Exception as exc:
            fresh_ok = False
            history.append({
                "timestamp": now(), "phase": "operator_cookie_bootstrap",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": False, "failure_class": classify_failure(None, exc),
                "error": str(exc),
            })

        print("[SESSION GUARD] Ejecutando login DVWA")
        try:
            login_result = recover(cfg)
            login_ok = bool(login_result.get("ok")) and login_result.get("returncode") == 0
            history.append({
                "timestamp": now(), "phase": "operator_login",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": login_ok,
                "failure_class": None if login_ok else classify_failure(login_result),
                "returncode": login_result.get("returncode"),
                "stdout_preview": (login_result.get("stdout") or "")[-1000:],
                "stderr_preview": (login_result.get("stderr") or "")[-500:],
            })
        except Exception as exc:
            login_ok = False
            history.append({
                "timestamp": now(), "phase": "operator_login",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": False, "failure_class": classify_failure(None, exc),
                "error": str(exc),
            })

        print("[SESSION GUARD] Aplicando y verificando security=low")
        try:
            status, _ = check_once(cfg)
            desired = str(cfg.get("authentication", {}).get("security") or "low").lower()
            verified = bool(
                status.get("ok")
                and status.get("authenticated")
                and status.get("security") == desired
            )
            history.append({
                "timestamp": now(), "phase": "operator_verify",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": verified, **status,
            })
        except Exception as exc:
            verified = False
            history.append({
                "timestamp": now(), "phase": "operator_verify",
                "attempt": attempt, "analysis_id": analysis_id,
                "ok": False, "failure_class": classify_failure(None, exc),
                "error": str(exc),
            })

        if verified:
            print("[SESSION GUARD] Recuperación manual exitosa")
            print("[SCHEDULER] Reanudando ciclo actual")
            history.append({
                "timestamp": now(), "phase": "operator_recovery",
                "event": "operator_recovery_success", "attempt": attempt,
                "analysis_id": analysis_id, "ok": True,
            })
            return True, "success"

        print(f"[SESSION GUARD] Reintento manual {attempt}/{total} no verificado.")

    history.append({
        "timestamp": now(), "phase": "operator_recovery",
        "event": "operator_recovery_exhausted",
        "attempt": total, "analysis_id": analysis_id, "ok": False,
    })
    print("[SESSION GUARD] FATAL: se agotaron los 3 reintentos manuales.")
    return False, "exhausted"


def reset_dvwa(cfg: dict[str, Any]) -> dict[str, Any]:
    """Reset the DVWA fixture using the current authenticated session.

    This belongs to the DVWA environment adapter. It does not expose the reset
    endpoint to the reasoner and does not alter challenge-resolution logic.
    """
    auth = cfg.get("authentication", {})
    target = cfg["target"]["base_url"].rstrip("/")
    mcp = cfg["target"]["kali_mcp_base"].rstrip("/")
    cookie = auth.get("cookie_jar") or COOKIE_JAR
    command = " ".join(shlex.quote(str(x)) for x in [
        "curl", "-ksS", "-L", "-m", "30", "-b", cookie, "-c", cookie,
        "-X", "POST", "--data", "create_db=Create+%2F+Reset+Database",
        target + "/setup.php",
    ])
    return mcp_exec(mcp, command, timeout=45)


def reset_and_recover(cfg: dict[str, Any], history: list[dict[str, Any]], *, analysis_id: str | None) -> bool:
    """Try two verified fixture resets before allowing a fatal session error."""
    for reset_attempt in range(1, RESET_ATTEMPTS + 1):
        print(f"[SESSION GUARD] DVWA reset attempt {reset_attempt}/{RESET_ATTEMPTS}")
        try:
            reset_result = reset_dvwa(cfg)
            reset_ok = bool(reset_result.get("ok")) and reset_result.get("returncode") == 0
            history.append({
                "timestamp": now(), "phase": "dvwa_reset", "attempt": reset_attempt,
                "analysis_id": analysis_id, "ok": reset_ok,
                "failure_class": None if reset_ok else classify_failure(reset_result),
                "returncode": reset_result.get("returncode"),
                "stdout_preview": (reset_result.get("stdout") or "")[-1000:],
                "stderr_preview": (reset_result.get("stderr") or "")[-500:],
            })
        except Exception as exc:
            reset_ok = False
            history.append({
                "timestamp": now(), "phase": "dvwa_reset", "attempt": reset_attempt,
                "analysis_id": analysis_id, "ok": False,
                "failure_class": classify_failure(None, exc), "error": str(exc),
            })

        # Always replace the cookie jar after a reset attempt. A reset invalidates
        # the old authenticated state even when the HTTP request itself succeeded.
        try:
            fresh = bootstrap_cookie(cfg)
            history.append({
                "timestamp": now(), "phase": "cookie_bootstrap", "attempt": reset_attempt,
                "analysis_id": analysis_id,
                "ok": bool(fresh.get("ok")) and fresh.get("returncode") == 0,
                "returncode": fresh.get("returncode"),
                "stderr_preview": (fresh.get("stderr") or "")[-500:],
            })
        except Exception as exc:
            history.append({
                "timestamp": now(), "phase": "cookie_bootstrap", "attempt": reset_attempt,
                "analysis_id": analysis_id, "ok": False,
                "failure_class": classify_failure(None, exc), "error": str(exc),
            })

        try:
            login_result = recover(cfg)
            login_ok = bool(login_result.get("ok")) and login_result.get("returncode") == 0
            history.append({
                "timestamp": now(), "phase": "post_reset_login", "attempt": reset_attempt,
                "analysis_id": analysis_id, "ok": login_ok,
                "failure_class": None if login_ok else classify_failure(login_result),
                "returncode": login_result.get("returncode"),
                "stdout_preview": (login_result.get("stdout") or "")[-1000:],
                "stderr_preview": (login_result.get("stderr") or "")[-500:],
            })
            if login_ok:
                status, _ = check_once(cfg)
                verified = bool(status.get("ok") and status.get("authenticated") and
                                status.get("security") == str(cfg.get("authentication", {}).get("security") or "low").lower())
                history.append({
                    "timestamp": now(), "phase": "post_reset_verify", "attempt": reset_attempt,
                    "analysis_id": analysis_id, "ok": verified, **status,
                })
                if verified:
                    print(f"[SESSION GUARD] DVWA reset attempt {reset_attempt}: OK")
                    return True
        except Exception as exc:
            history.append({
                "timestamp": now(), "phase": "post_reset_login", "attempt": reset_attempt,
                "analysis_id": analysis_id, "ok": False,
                "failure_class": classify_failure(None, exc), "error": str(exc),
            })
    return False


def persist(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run(config_path: str, attempts: int = 3, rotate: bool = False, analysis_id: str | None = None) -> int:
    cfg = load_config(config_path)
    auth = cfg.get("authentication", {})
    if not auth.get("enabled", False):
        print("[SESSION GUARD] Authentication disabled; check skipped.")
        return 0

    desired = str(auth.get("security") or "low").lower()
    history: list[dict[str, Any]] = []

    if rotate:
        print(f"[SESSION ROTATION] Analysis Item: {analysis_id or 'UNKNOWN'}")
        print("[SESSION ROTATION] Creando nueva sesión DVWA y reemplazando la cookie anterior")
        try:
            recovered = recover(cfg)
            history.append({
                "timestamp": now(), "attempt": 0, "phase": "forced_rotation",
                "analysis_id": analysis_id, "ok": recovered.get("ok"),
                "returncode": recovered.get("returncode"),
                "stdout_preview": (recovered.get("stdout") or "")[-1000:],
                "stderr_preview": (recovered.get("stderr") or "")[-500:],
            })
            if not recovered.get("ok") or recovered.get("returncode") != 0:
                print("[SESSION ROTATION] Login normal falló; iniciando recuperación del laboratorio")
                if reset_and_recover(cfg, history, analysis_id=analysis_id):
                    persist({"version": SESSION_GUARD_VERSION, "status": "OK_AFTER_RESET", "analysis_id": analysis_id,
                             "desired_security": desired, "verified_at": now(), "history": history})
                    return 0
                print("[SESSION ROTATION] Recuperación automática agotada.")
                operator_ok, operator_outcome = operator_reset_and_recover(
                    cfg, history, analysis_id=analysis_id
                )
                if operator_ok:
                    persist({"version": SESSION_GUARD_VERSION, "status": "OK_AFTER_OPERATOR_RESET",
                             "analysis_id": analysis_id, "desired_security": desired,
                             "verified_at": now(), "history": history})
                    return 0
                persist({"version": SESSION_GUARD_VERSION,
                         "status": "OPERATOR_ABORTED" if operator_outcome == "aborted" else "FAILED",
                         "analysis_id": analysis_id, "desired_security": desired,
                         "verified_at": now(), "operator_outcome": operator_outcome,
                         "history": history})
                return 1
        except Exception as exc:
            history.append({"timestamp": now(), "attempt": 0, "phase": "forced_rotation",
                            "analysis_id": analysis_id, "ok": False,
                            "failure_class": classify_failure(None, exc), "error": str(exc)})
            print(f"[SESSION ROTATION] Error de transporte: {exc}; iniciando recuperación del laboratorio")
            if reset_and_recover(cfg, history, analysis_id=analysis_id):
                persist({"version": SESSION_GUARD_VERSION, "status": "OK_AFTER_RESET", "analysis_id": analysis_id,
                         "desired_security": desired, "verified_at": now(), "history": history})
                return 0
            print("[SESSION ROTATION] Recuperación automática agotada.")
            operator_ok, operator_outcome = operator_reset_and_recover(
                cfg, history, analysis_id=analysis_id
            )
            if operator_ok:
                persist({"version": SESSION_GUARD_VERSION, "status": "OK_AFTER_OPERATOR_RESET",
                         "analysis_id": analysis_id, "desired_security": desired,
                         "verified_at": now(), "history": history})
                return 0
            persist({"version": SESSION_GUARD_VERSION,
                     "status": "OPERATOR_ABORTED" if operator_outcome == "aborted" else "FAILED",
                     "analysis_id": analysis_id, "desired_security": desired,
                     "verified_at": now(), "operator_outcome": operator_outcome,
                     "history": history})
            return 1

    for attempt in range(1, attempts + 1):
        try:
            status, _ = check_once(cfg)
        except Exception as exc:
            status = {"ok": False, "authenticated": False, "security": None, "error": str(exc)}

        row = {"timestamp": now(), "attempt": attempt, "phase": "check", **status}
        history.append(row)
        print("[SESSION GUARD]")
        print(f"Authenticated : {'YES' if status.get('authenticated') else 'NO'}")
        print(f"Security      : {(status.get('security') or 'UNKNOWN').upper()}")

        if status.get("ok") and status.get("authenticated") and status.get("security") == desired:
            print("Result        : OK")
            persist({"version": SESSION_GUARD_VERSION, "analysis_id": analysis_id, "status": "OK", "desired_security": desired, "verified_at": now(), "history": history})
            return 0

        print("Result        : RECOVER")
        try:
            recovered = recover(cfg)
            recovery_row = {
                "timestamp": now(), "attempt": attempt, "phase": "recover",
                "ok": recovered.get("ok"), "returncode": recovered.get("returncode"),
                "stdout_preview": (recovered.get("stdout") or "")[-1000:],
                "stderr_preview": (recovered.get("stderr") or "")[-500:],
            }
        except Exception as exc:
            recovery_row = {"timestamp": now(), "attempt": attempt, "phase": "recover", "ok": False, "error": str(exc)}
        history.append(recovery_row)

    print("[SESSION GUARD] La recuperación normal falló; iniciando doble reset verificado")
    if reset_and_recover(cfg, history, analysis_id=analysis_id):
        persist({"version": SESSION_GUARD_VERSION, "analysis_id": analysis_id,
                 "status": "OK_AFTER_RESET", "desired_security": desired,
                 "verified_at": now(), "history": history})
        return 0

    print("[SESSION GUARD] Recuperación automática agotada; evaluando fallback del operador.")
    operator_ok, operator_outcome = operator_reset_and_recover(
        cfg, history, analysis_id=analysis_id
    )
    if operator_ok:
        persist({"version": SESSION_GUARD_VERSION, "analysis_id": analysis_id,
                 "status": "OK_AFTER_OPERATOR_RESET", "desired_security": desired,
                 "verified_at": now(), "history": history})
        return 0

    print("[SESSION GUARD] FATAL: no fue posible restablecer la sesión DVWA.")
    persist({"version": SESSION_GUARD_VERSION, "analysis_id": analysis_id,
             "status": "OPERATOR_ABORTED" if operator_outcome == "aborted" else "FAILED",
             "desired_security": desired, "verified_at": now(),
             "operator_outcome": operator_outcome, "history": history})
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.environ.get("BUGTRACEAI_CONFIG", str(DEFAULT_CONFIG)))
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--parse-file", help="Only parse a saved DVWA response (self-test/debug).")
    parser.add_argument("--rotate", action="store_true", help="Fuerza una sesión nueva antes del Analysis Item.")
    parser.add_argument("--analysis-id", help="Identificador A-xxxx asociado a la rotación.")
    args = parser.parse_args()
    if args.parse_file:
        print(json.dumps(parse_effective_page(Path(args.parse_file).read_text(errors="replace")), indent=2))
        return 0
    return run(args.config, args.attempts, rotate=args.rotate, analysis_id=args.analysis_id)


if __name__ == "__main__":
    raise SystemExit(main())
