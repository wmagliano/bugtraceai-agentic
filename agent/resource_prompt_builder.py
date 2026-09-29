#!/usr/bin/env python3
"""Prompt Builder V1.7.4: contexto mínimo, determinístico y centrado en recurso."""
import json
from executor_capabilities import capabilities_payload
from typing import Any, Dict

ALLOWED_STATES = ["UNKNOWN","MAPPED","HYPOTHESIS_ACTIVE","TESTING","EVIDENCE_COLLECTED","CONFIRMED","WAITING_OPERATOR","EXPLOITING","EXPLOITABLE","DOCUMENTED","COMPLETED","INCONCLUSIVE"]


def _clip(v: Any, n: int) -> str:
    text = "" if v is None else str(v)
    return text if len(text) <= n else text[:n] + "...[truncated]"




def _active_analysis_item(k: Dict[str, Any], resource: str) -> Dict[str, Any]:
    active_id = k.get("active_analysis_id")
    for item in k.get("analysis_queue") or []:
        if not isinstance(item, dict):
            continue
        if active_id and item.get("analysis_id") == active_id:
            return item
        if resource and item.get("entry_url") == resource:
            return item
    return {}


def _validation_history(k: Dict[str, Any], resource: str, limit: int = 3):
    """Resumen explícito de pruebas previas del expediente activo.

    No interpreta resultados: presenta al LLM qué URL/comando probó, el estado
    de ejecución, una muestra del resultado y si hubo evidencia verificada.
    """
    item = _active_analysis_item(k, resource)
    rows = []
    for cmd in (item.get("commands") or [])[-limit:]:
        if not isinstance(cmd, dict):
            continue
        verified = cmd.get("verified_evidence") or []
        rows.append({
            "attempt": len(rows) + max(1, len(item.get("commands") or []) - limit + 1),
            "tested_url": cmd.get("tested_url"),
            "command": _clip(cmd.get("command", ""), 600),
            "execution_status": cmd.get("execution_status"),
            "ok": cmd.get("ok"),
            "returncode": cmd.get("returncode"),
            "result_excerpt": _clip(cmd.get("stdout_preview", ""), 1200),
            "verified_evidence": verified,
            "reason": _clip(cmd.get("reason", ""), 300),
        })
    return rows

def _completed_urls(k: Dict[str, Any]):
    out=[]
    for x in k.get("completed_urls", []):
        if isinstance(x, str): out.append(x)
        elif isinstance(x, dict) and x.get("url"): out.append(x["url"])
    return out


def _resource_string(value: Any) -> str:
    """Normaliza recursos persistidos como URL string u objeto runtime."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("resource", "url", "target", "endpoint"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return ""


def _active_resource(k: Dict[str, Any]) -> str:
    active = _resource_string(k.get("active_resource"))
    if active:
        return active
    visited=k.get("visited_urls") or []
    completed=set(_completed_urls(k))
    states=k.get("resource_state") or {}
    # prefer latest non-completed visited URL
    for raw in reversed(visited):
        u = _resource_string(raw)
        if not u:
            continue
        raw_state = states.get(u)
        st=(raw_state or {}).get("state") if isinstance(raw_state, dict) else raw_state
        if u not in completed and st not in {"COMPLETED","INCONCLUSIVE"}:
            return u
    if visited:
        last = _resource_string(visited[-1])
        if last:
            return last
    return _resource_string((k.get("scope") or {}).get("target_base", ""))


def _relevant_memory(k, resource, limit=12):
    items=[]
    for x in reversed(k.get("cognitive_knowledge") or []):
        if not isinstance(x, dict): continue
        if x.get("resource") in {resource, None, ""}:
            items.append({a:x.get(a) for a in ("kind","resource","text","confidence","status") if x.get(a) is not None})
        if len(items)>=limit: break
    return list(reversed(items))


def _recent_observations(k, resource, limit=4):
    pools=[]
    for key in ("mcp_command_observations","mcp_observations","command_observations","mcp_interior_observations"):
        for x in k.get(key) or []:
            if not isinstance(x, dict): continue
            cmd=str(x.get("command", ""))
            url=x.get("url") or ""
            if resource and resource not in cmd and resource != url: continue
            pools.append({
                "source": key,
                "ok": x.get("ok"),
                "returncode": x.get("returncode"),
                "command": _clip(cmd, 500),
                "stdout": _clip(x.get("stdout") or x.get("stdout_preview") or x.get("evidence_hint") or "", 1000),
                "stderr": _clip(x.get("stderr") or x.get("stderr_preview") or "", 300),
            })
    return pools[-limit:]


def _evidence_review_gate(k: Dict[str, Any], resource: str) -> Dict[str, Any]:
    item = _active_analysis_item(k, resource)
    session = item.get("cognitive_session") or {}
    cycles = session.get("cycles") or []
    latest = cycles[-1] if cycles else {}
    result = latest.get("result") or {}
    predicate = result.get("predicate_result") or {}
    reflection = latest.get("reflection") or {}
    matched = predicate.get("evaluated") is True and predicate.get("matched") is True
    promoted = bool(reflection.get("evidence_candidate"))
    return {
        "required": bool(matched and not promoted),
        "experiment_status": predicate.get("experiment_status"),
        "evaluated": predicate.get("evaluated"),
        "matched": predicate.get("matched"),
        "meaning": predicate.get("meaning"),
        "excerpt": _clip(predicate.get("excerpt", ""), 500),
        "instruction": "Revisar y decidir promoción/veredicto antes de repetir o lanzar otro experimento equivalente." if matched and not promoted else None,
    }

def build_resource_context(k: Dict[str, Any]) -> Dict[str, Any]:
    r=_active_resource(k)
    url_context = k.get("url_context") or {}
    if not isinstance(url_context, dict):
        url_context = {}
    ctx=url_context.get(r, {})
    if not isinstance(ctx, dict):
        ctx = {}
    resource_state = k.get("resource_state") or {}
    if not isinstance(resource_state, dict):
        resource_state = {}
    state=resource_state.get(r, {})
    if not isinstance(state, dict): state={"state": state}
    visited_set={_resource_string(x) for x in (k.get("visited_urls") or []) if _resource_string(x)}
    completed_set=set(_completed_urls(k))
    candidates=[]
    for raw in (k.get("candidate_urls") or []):
        u=_resource_string(raw)
        if u and u not in visited_set and u not in completed_set:
            candidates.append(u)
        if len(candidates) >= 8:
            break
    return {
        "current_resource": r,
        "current_state": state,
        "resource_goal": (k.get("resource_goals") or {}).get(r),
        "reference_exploitation": (k.get("reference_exploitation") or {}).get(r),
        "reference_exploit_counter": (k.get("reference_exploit_counters") or {}).get(r),
        "operator_checkpoint": k.get("latest_operator_checkpoint"),
        "page": {
            "status_line": ctx.get("status_line"),
            "title": ctx.get("title"),
            "forms": ctx.get("forms", [])[:4],
            "query_params": ctx.get("query_params", {}),
            "visible_text_excerpt": _clip(ctx.get("visible_text_excerpt", ""), 1200),
            "observation_quality": ctx.get("observation_quality"),
            "body_indicators": ctx.get("body_indicators", {}),
        },
        "relevant_memory": _relevant_memory(k, r),
        "recent_observations": _recent_observations(k, r),
        "validation_history": _validation_history(k, r, int(__import__("os").environ.get("BUGTRACEAI_REASONER_HISTORY_DEPTH", "3"))),
        "resource_errors": (k.get("resource_errors") or {}).get(r, {}),
        "llm_errors": (k.get("llm_errors") or {}).get(r, {}),
        "successful_commands": [
            _clip(x.get("command", ""), 500) for x in (k.get("mcp_command_observations") or [])
            if isinstance(x, dict) and x.get("ok") and (not r or r in str(x.get("command", "")))
        ][-8:],
        "next_candidates": candidates,
        "autonomous_attempt": {
            "mcp_executions": int((((k.get("autonomous_resource_counters") or {}).get(r) or {}).get("mcp_executions", 0)) or 0),
            "max_mcp_commands": int(__import__("os").environ.get("BUGTRACEAI_MAX_MCP_COMMANDS", "6")),
            "specialized_last_attempt": __import__("os").environ.get("BUGTRACEAI_SPECIALIZED_LAST_ATTEMPT", "1") in {"1","true","yes","on"},
        },
        "operational_state": {
            "authenticated": (k.get("session") or {}).get("authenticated"),
            "credential_material_available": bool((k.get("session") or {}).get("cookie_location")),
            "authentication": {
                "available": bool((k.get("session") or {}).get("authenticated")),
                "mechanism": "cookie_jar" if (k.get("session") or {}).get("cookie_location") else None,
                "cookie_jar": (k.get("session") or {}).get("cookie_jar") or "/tmp/bugtraceai-session/dvwa_cookie.txt",
                "reuse_rule": "Si el experimento requiere autenticación, reutilizar este cookie jar; no inventar cookies ni PHPSESSID."
            },
            "resource_mapped": bool(ctx),
            "mcp_available": True,
        },
        "evidence_review_gate": _evidence_review_gate(k, r),
        "analysis_item": _active_analysis_item(k, r),
    }


def build_resource_prompt(k: Dict[str, Any], actions: Dict[str,str], version: str) -> str:
    c=build_resource_context(k)
    contract={
      "reflection":{"observation":"string","interpretation":"string","hypothesis_type":"VULNERABILITY|DISCOVERY|ATTACK_SURFACE|INFORMATIONAL","hypothesis_effect":"SUPPORTED|WEAKENED|REFUTED|NOT_EVALUATED","learned_fact":"string","evidence_candidate":"boolean","evidence_reason":"string|null","assessment":"CONTINUE|CONFIRMED|NOT_CONFIRMED|INCONCLUSIVE|NO_FINDING","confidence":"LOW|MEDIUM|HIGH","next_requirement":"string|null"},
      "vulnerability_verdict":{"status":"UNASSESSED|CONFIRMED|NO_FINDING|INCONCLUSIVE","confidence":"LOW|MEDIUM|HIGH|null","summary":"string","evidence_ids":["EVID-id"]},
      "exploitation":{"status":"CONFIRMED|LIMITED|NOT_CONFIRMED|NOT_TESTABLE|NOT_APPLICABLE","summary":"string","command_ids":[],"result_ids":[]},
      "capability_assessment":{"note":"OPTIONAL_DIAGNOSTIC_ONLY_NOT_AUTHORITATIVE"},
      "finding_classification":{"type":"VULNERABILITY|DISCLOSURE|MISCONFIGURATION|EXPOSURE|INFORMATIONAL","summary":"string|null"},
      "next_actions":[{"action":"una acción permitida","reason":"motivo técnico","expected_evidence":"obligatorio en comandos experimentales; definido por el LLM","otros_campos":"según allowed_actions"}]
    }
    rules=[
      "Devuelve solo un objeto JSON válido, sin markdown ni texto adicional.",
      "Si operational_state.authentication.available=true y una solicitud requiere autenticación, usá operational_state.authentication.cookie_jar (por ejemplo curl -b RUTA). No inventes PHPSESSID, cabeceras Cookie ni tokens de sesión.",
      "Si predicate_result.experiment_status es NOT_EXECUTED o TRANSPORT_ERROR, la hipótesis no fue evaluada: usa hypothesis_effect=NOT_EVALUATED, evidence_candidate=false y adapta la estrategia sin tratar matched como falso científico.",
      "Cuando predicate_result.evaluated=true y matched=true, primero revisá esa evidencia. No propongas otro comando equivalente antes de decidir evidence_candidate, evidence_reason y assessment.",
      "SELF-VERDICT r4b: después de cada resultado evaluado, antes de elegir otra acción, hacé una revisión explícita de cierre usando la evidencia acumulada del Analysis Item: (1) ¿la hipótesis ya está suficientemente demostrada o refutada?, (2) ¿existe alguna contradicción concreta?, (3) ¿una prueba adicional aportaría información realmente nueva? Expresá la respuesta mediante reflection.assessment, confidence, evidence_candidate, evidence_reason y next_requirement.",
      "SELF-VERDICT r4b: si considerás la vulnerabilidad confirmada con evidencia específica y reproducible, no sigas experimentando por inercia: usa assessment=CONFIRMED, evidence_candidate=true, next_requirement vacío y finalize_analysis. Si todavía falta una condición concreta, usa CONTINUE y describila en next_requirement. Si la evidencia no permite resolverla dentro de las capacidades disponibles, usa INCONCLUSIVE. Nunca confirmes solo por intuición, nombre de recurso, versión o ausencia de contradicciones.",
      "Si la evidencia es específica y suficiente, usa reflection.evidence_candidate=true, assessment=CONFIRMED y next_actions[0].action=finalize_analysis. Si es positiva pero insuficiente, usa assessment=CONTINUE y propone un experimento diferente que resuelva exactamente la incertidumbre restante.",
      "SEMÁNTICA DE CONFIRMACIÓN v3.0.3e: CONFIRMED exige evidencia específica y reproducible de la condición de seguridad vulnerable definida por la hipótesis activa; no exige demostrar toda la explotación ni el impacto final. Una mera versión, intuición, HTTP 200, precondición aislada o señal ambigua no alcanza. Si la condición vulnerable está demostrada, conserva CONFIRMED aunque la explotación posterior sea limitada, no confirmada o no testeable.",
      "SEMÁNTICA DE EVIDENCIA v3.0.3d: evidence_candidate=true solo cuando evidence_reason identifica (a) la observación concreta, (b) el efecto de seguridad que demuestra y (c) por qué esa observación distingue la hipótesis de un comportamiento benigno/esperado. Si no podés expresar esas tres partes con la evidencia capturada, evidence_candidate=false.",
      "SEMÁNTICA TERMINAL v3.0.3e: una limitación instrumental solo obliga a INCONCLUSIVE cuando impide decidir si existe la vulnerabilidad. Si la vulnerabilidad ya quedó demostrada, una limitación de navegador, callback, interacción, herramienta o runtime afecta únicamente el eje de explotación y debe expresarse como exploitation=NOT_TESTABLE o LIMITED, sin revocar vulnerability=CONFIRMED.",
      "ARCHITECTURE GATE v3.0.3h: las capacidades instrumentales son autoridad exclusiva del runtime. No decidas ni declares si BugTraceAI posee una capacidad. Razona libremente sobre la vulnerabilidad y describe exactamente qué evidencia observaste; el runtime clasificará de forma independiente si la validación autónoma está soportada o requiere validación del operador.",
      "ARCHITECTURE GATE v3.0.3h: no confundas evidencia observada con comportamiento inferido. Tu responsabilidad es el razonamiento de vulnerabilidad; la decisión SUPPORTED/REQUIRES_OPERATOR_VALIDATION/UNSUPPORTED pertenece únicamente al runtime.",
      "CLASIFICACIÓN v3.0.3h: usa DISCLOSURE para exposición confirmada de información útil (por ejemplo configuración, versiones, rutas o metadatos) cuando no corresponda modelarla como una cadena de explotación; en esos casos exploitation=NOT_APPLICABLE. La clasificación no sustituye la evidencia ni eleva por sí sola severidad o vulnerabilidad.",
      "SEMÁNTICA DE CIERRE v3.0.3e: no confundas vulnerabilidad con explotación. CONFIRMED describe una condición de seguridad vulnerable demostrada del recurso; la ejecución, impacto o cadena posterior pertenecen al eje de explotación. No exijas evidencia de explotación para conceder CONFIRMED cuando la condición vulnerable ya fue observada de forma específica y reproducible.",
      "Si assessment es NOT_CONFIRMED, NO_FINDING o INCONCLUSIVE y ya no corresponde experimentar, usa finalize_analysis para cerrar el Analysis Item. Nunca uses finalize_analysis con assessment=CONTINUE.",
      "REGLA OBLIGATORIA DVWA UPLOAD: si current_resource contiene /vulnerabilities/upload/, cualquier envío multipart DEBE usar exactamente assets/benign_phpinfo.php. No generes shell.php, webshells, PHP inline, /dev/stdin ni rutas alternativas. Para este Analysis Item, y solo para este, el scope de navegación/validación se amplía a cualquier ruta HTTP(S) del mismo host raíz del target; otros hosts o subdominios siguen fuera de scope. Podés recuperar o abrir el artefacto benigno subido si la aplicación revela una URL dentro de ese mismo host y ello aporta evidencia nueva. No uses el Upload como pivote hacia otros Analysis Items ni hacia hosts externos.",
      "Para CSP separá condición vulnerable y explotación. Si la política efectiva permite la condición insegura relevante y el agente demuestra control/aceptación de la entrada o recurso necesario, vulnerability=CONFIRMED. Solo si se observa ejecución JavaScript atribuible, exploitation=CONFIRMED; sin navegador instrumentado puede quedar NOT_TESTABLE. Para comprobar si una fuente sería permitida no hace falta que el servidor externo exista: podés usar 127.0.0.1, localhost o un origen reservado/no enrutable como example.invalid, siempre dentro de un experimento que no abandone el Analysis Item. No interpretes un fallo de conexión como bloqueo CSP; la evidencia primaria debe provenir de la política observada o de una señal del navegador cuando esté disponible.",
      "REGLA GENERAL DE MECANISMOS DERIVADOS: cuando una prueba dependa de un token, hash, firma, checksum, nonce, valor oculto o transformación que todavía no comprendés, no inventes el valor ni repitas payloads. Primero inspeccioná la lógica disponible, formulá cómo se deriva el valor y ejecutá un experimento local reproducible para calcularlo o verificarlo. Solo después usá el valor observado en la solicitud contra el recurso.",
      "Para JavaScript clasificá el código como LEGIBLE, MINIFIED u OBFUSCATED. Si no podés interpretar con confianza, registrá OBFUSCATED y solicitá desofuscación o revisión manual; no inventes la lógica.",
      "ANÁLISIS NEUTRAL DE LÓGICA CLIENTE: cuando una solicitud dependa de JavaScript, identificá los scripts relevantes, el evento que inicia el flujo, las fuentes de entrada, las transformaciones verificadas, los campos o encabezados resultantes y la señal observable de éxito o fracaso. Reconstruí el flujo desde la acción hasta la petición final antes de enviarla.",
      "En lógica cliente no inventes tokens, hashes, claves, nonces, algoritmos ni valores intermedios; no pruebes listas arbitrarias de valores. Reproducí solamente transformaciones observadas en el código y validá cada dependencia pendiente antes de construir la solicitud final.",
      "No consideres resuelto un desafío de lógica cliente por HTTP 200. La confirmación requiere una respuesta funcional distinguible o evidencia específica de la aplicación. Si aún existen dependencias no resueltas, inspeccioná más o cerrá INCONCLUSIVE en vez de adivinar.",
      "Máximo una acción en next_actions.",
      "La unidad de razonamiento es exclusivamente el Analysis Item activo. No mezcles comandos, hipótesis, reflexiones ni evidencia detallada de otros items.",
      "Si analysis_item.cognitive_session contiene un ciclo AWAITING_REFLECTION, completá reflection interpretando ese último resultado antes de proponer la siguiente acción.",
      "La reflexión debe distinguir observación cruda, interpretación, efecto sobre la hipótesis, hecho aprendido y necesidad siguiente. No copies stdout completo como reflexión.",
      "Antes de elegir la siguiente acción, compará explícitamente el último resultado con validation_history: indicá qué hipótesis descartás, cuál mantenés, qué cambió y qué información nueva aportará la próxima prueba.",
      "Si la próxima acción es equivalente a una ya registrada, solo puede repetirse cuando la reflexión explique qué condición cambió y por qué el nuevo intento puede producir evidencia distinta.",
      "Una respuesta con un resultado MCP pendiente y reflection vacía es inválida conceptualmente.",
      "El nombre o la ruta del recurso no prueba una clase de vulnerabilidad. Clasificá únicamente cuando la evidencia lo permita.",
      "SEMANTIC CLAIM GATE v3.0.4: clasificá la hipótesis activa con reflection.hypothesis_type. Usa VULNERABILITY solo cuando la afirmación describe una condición de seguridad concreta del recurso que puede ser confirmada o refutada. Usa DISCOVERY cuando la afirmación solo demuestra que existen/enlazan otros recursos; ATTACK_SURFACE cuando describe superficie, vectores potenciales o mecanismos disponibles sin demostrar una condición vulnerable; INFORMATIONAL para hechos descriptivos sin condición de seguridad demostrada.",
      "SEMANTIC CLAIM GATE v3.0.4: DISCOVERY o ATTACK_SURFACE pueden quedar SUPPORTED y generar nuevos Analysis Items, pero nunca equivalen por sí solos a Vulnerability=CONFIRMED. Si una hipótesis de discovery/superficie se confirma, incorporá el aprendizaje, encolá los recursos relevantes y continúa/reformula hacia una hipótesis VULNERABILITY si existe evidencia concreta; si no existe una condición vulnerable del recurso activo, no lo marques CONFIRMED.",
      "SEMANTIC CLAIM GATE v3.0.4: para assessment=CONFIRMED es obligatorio reflection.hypothesis_type=VULNERABILITY y evidence_reason debe identificar una condición de seguridad específica del recurso activo, no solamente la existencia de endpoints, módulos, versiones, enlaces o vectores potenciales.",
      "Una coincidencia de versión, banner, fingerprint o CVE solo crea o refuerza una hipótesis (SUSPECTED/E1); nunca equivale por sí sola a CONFIRMED. Validá precondiciones y obtené evidencia técnica reproducible del comportamiento vulnerable.",
      "Separá siempre dos ejes jerárquicos: vulnerabilidad y explotación. Como salida final pública, vulnerabilidad solo puede ser CONFIRMED, NO_FINDING o INCONCLUSIVE. Solo si vulnerabilidad=CONFIRMED, explotación puede ser CONFIRMED, LIMITED, NOT_CONFIRMED o NOT_TESTABLE. Si vulnerabilidad es NO_FINDING o INCONCLUSIVE, explotación debe ser NOT_APPLICABLE. Es una invariante: nunca puede existir explotación sin vulnerabilidad confirmada.",
      "NO_FINDING es una afirmación fuerte, comparable a CONFIRMED. Proponelo únicamente con evidencia negativa reproducible, precondiciones verificadas, cobertura declarada >= 0.90, al menos dos pruebas relevantes, cero errores de ejecución, cero contradicciones y ninguna alternativa razonable pendiente. Incluí no_finding_basis con coverage, reproducible, preconditions_verified, unresolved_alternatives y contradictions. Si falta cualquiera de estos elementos, cerrá INCONCLUSIVE.",
      "Ante limitaciones de capacidad (segunda sesión, navegador real, interacción manual, herramienta especializada o análisis externo), no improvises una implementación equivalente. Si la limitación impide decidir la vulnerabilidad, cerrá INCONCLUSIVE. Si la vulnerabilidad ya está CONFIRMED y la limitación solo impide demostrar explotación, conserva CONFIRMED y usa exploitation=NOT_TESTABLE; usa LIMITED cuando exista efecto parcial demostrado.",
      "La explotación es deseable pero secundaria y siempre posterior a la confirmación. No rebajes una vulnerabilidad CONFIRMED porque la explotación falle o no pueda comprobarse: usa exploitation=NOT_CONFIRMED si fue evaluada sin demostración, LIMITED si fue parcial, NOT_TESTABLE si falta capacidad instrumental y CONFIRMED solo con efecto controlado observable.",
      "Para vulnerability=CONFIRMED exigí evidencia específica y reproducible equivalente a E3 de la condición vulnerable. Para exploitation=CONFIRMED exigí efecto/impacto controlado atribuible equivalente a E5. La primera no depende de alcanzar la segunda.",
      "Mantén foco exclusivo en current_resource; no cambies de recurso salvo que esté COMPLETED/INCONCLUSIVE o no se pueda avanzar.",
      "No repitas comandos exitosos listados en successful_commands.",
      "review_forms puede utilizarse una sola vez por recurso después del mapeo. Si sus formularios ya aparecen en resource_context.page.forms, no vuelvas a solicitarlo: formula una hipótesis, ejecuta un experimento diferente o finaliza.",
      "Nunca cambies el nivel de seguridad, PHPIDS, la base de datos ni borres logs del laboratorio durante el análisis. Esas son mutaciones globales fuera del experimento activo.",
      "Si authentication.cookie_jar está disponible, todo comando autenticado debe usar -b con esa ruta. Está prohibido inventar Cookie o PHPSESSID.",
      "Para /vulnerabilities/upload/ usa submit_benign_upload. No construyas manualmente multipart, shells ni archivos alternativos.",
      "Para /vulnerabilities/brute/ utilizá exclusivamente las credenciales controladas username=admin y password=password. No pruebes, generes ni consumas otras contraseñas. Confirmá mediante una señal observable de autenticación aceptada o diferencia de respuesta, sin alterar la credencial operativa.",
      "Para /vulnerabilities/csrf/ utilizá exclusivamente admin/password. En cualquier cambio de contraseña enviá password como contraseña actual, nueva y confirmación. Confirmá únicamente mediante la respuesta observable del recurso, por ejemplo Password Changed., sin alterar admin/password ni depender de setup.php.",
      "Para /vulnerabilities/captcha/ utilizá exclusivamente admin/password. Si el flujo solicita una contraseña nueva o confirmación, ambos valores deben ser password. No dejes ninguna credencial diferente ni dependas de setup.php para restaurarla. Confirmá el bypass o cambio mediante evidencia observable del mismo recurso.",
      "Para hipótesis de Command Injection, la LLM decide libremente herramienta, separador, payload y evidencia. Evitá construir pruebas que dependan de utilidades cuya existencia no fue observada, comandos con salida ambigua, efectos secundarios innecesarios, sintaxis incompatible con executor_capabilities o señales que puedan aparecer sin ejecución real. Priorizá una evidencia objetiva, atribuible y distinguible; después de un fallo evaluado, no repitas la misma estrategia con variaciones equivalentes.",
      "Para /vulnerabilities/fi/ el primer experimento debe usar /etc/passwd como valor inicial del parámetro de inclusión y buscar una señal estructurada equivalente a root:[^:]*:0:0:. Solo después de un fallo evaluado probá variantes de ruta o wrapper.",
      "Usá validation_history para comparar cada prueba previa con su resultado. Si no hubo evidencia verificada, adaptá la estrategia sin asumir éxito ni repetir una prueba equivalente.",
      "Solo tratá verified_evidence como evidencia técnica extraída directamente del resultado; result_excerpt es contexto y requiere interpretación.",
      "Antes de proponer propose_mcp_command o propose_command, definí expected_evidence: una señal observable concreta y su significado. El runtime evalúa mecánicamente el predicado; vos interpretás el resultado en el ciclo siguiente.",
      "Matchers permitidos para expected_evidence: contains con value, not_contains con value, regex con pattern y returncode con value entero. No uses grep o filtros shell para evaluar la señal: declarala en expected_evidence.",
      "predicate_result.matched es una señal mecánica, no un veredicto. Revisá también excerpt, match_count, returncode y el contexto del experimento antes de concluir.",
      "La confirmación de vulnerabilidad y la explotación son recorridos separados. Solo puede iniciarse explotación si vulnerability_verdict.status=CONFIRMED. Si el veredicto es NOT_CONFIRMED, NO_FINDING o INCONCLUSIVE, no explotes. EXPLOITABLE significa que una explotación controlada fue confirmada; COMPLETED solo significa cierre operativo. En autonomous_mode, una vulnerabilidad CONFIRMED puede documentarse/cerrarse sin explotación. Solo usa ask_operator en modo operador.",
      "Después de una autorización, realizá solo pruebas que aporten evidencia nueva y respetá el límite operativo del recurso.",
      "Errores llm_format_error/llm_transport_error no significan INCONCLUSIVE.",
      "Preservá los prerrequisitos operativos de la sesión activa; no invalides deliberadamente el acceso necesario para continuar el laboratorio.",
      "Construí los comandos de acuerdo con executor_capabilities. Los operadores declarados como permitidos pueden utilizarse; no uses capacidades bloqueadas o ausentes. La sustitución de comandos $() está habilitada experimentalmente: usala solo para derivaciones o lecturas necesarias y verificables dentro del experimento, no para ocultar acciones ni reemplazar el razonamiento explícito.",
      "operator_verdict documenta/cierra tras el checkpoint en modo operador. En modo autónomo el cierre CONFIRMED es atómico y no requiere checkpoint.",
      "Podés elegir libremente solicitudes HTTP manuales o herramientas automatizadas disponibles en Kali cuando lo consideres más eficiente; no existe una política fija de herramientas.",
      "Si autonomous_attempt.mcp_executions == autonomous_attempt.max_mcp_commands - 1 y specialized_last_attempt=true, este es el último intento: preferí una herramienta especializada o automatizada disponible en Kali, elegida libremente por vos, siempre que sea aplicable y aporte evidencia nueva. No repitas una prueba manual equivalente.",
      "El contrato mínimo obligatorio contiene reflection y exactamente una acción en next_actions. El runtime deriva y conserva los demás campos compatibles.",
      "No confundas análisis terminado con vulnerabilidad confirmada: COMPLETED puede coexistir con NO_FINDING, NOT_CONFIRMED o CONFIRMED; INCONCLUSIVE debe conservar la incertidumbre técnica.",
      "Cuando necesites construir un artefacto de prueba cuyo contenido incluya caracteres incompatibles con el contrato de shell, podés serializar el contenido en Base64 y reconstruirlo en Kali con una tubería equivalente a echo <contenido_base64> | base64 -d > <ruta_temporal_permitida>. Verificá que base64 figure en executor_capabilities.available_tools, utilizá únicamente rutas temporales permitidas y tratá el artefacto reconstruido como parte del experimento activo. Esta capacidad es genérica y no prescribe contenido, extensión, vulnerabilidad ni objetivo.",
    ]
    payload={
      "version":version,
      "role":"Operator Guided Cognitive Security Validation Agent sobre un objetivo autorizado",
      "allowed_actions":actions,
      "allowed_states":ALLOWED_STATES,
      "decision_contract":contract,
      "rules":rules,
      "executor_capabilities":capabilities_payload(),
      "upload_artifact_policy":{
        "mode":"REQUIRED_FOR_DVWA_UPLOAD",
        "resource_match":"/vulnerabilities/upload/",
        "artifact_id":"benign_phpinfo_php",
        "artifact_path":"assets/benign_phpinfo.php",
        "must_use_for_multipart":True,
        "forbidden":["shell.php","webshell","PHP inline","/dev/stdin","invented local paths"],
        "validation_stages":["UPLOAD_ACCEPTED"],
        "response_marker":"succesfully uploaded!",
        "same_response_only":True,
        "follow_uploaded_resource":True,
        "same_target_host_only":True,
        "evaluate_execution":True
      },
      "brute_force_policy":{"username":"admin","password":"password","must_use_fixed_credentials":True,"must_use_wordlist":False,"single_password_guesses_forbidden":False},
      "csrf_validation_policy":{"username":"admin","current_password":"password","new_password":"password","response_marker":"Password Changed.","preserve_operational_credentials":True},
      "captcha_validation_policy":{"username":"admin","current_password":"password","new_password":"password","preserve_operational_credentials":True},
      "first_attempt_policies":{"command_injection":{"goal":"read /etc/passwd","expected_regex":"root:[^:]*:0:0:"},"lfi":{"value":"/etc/passwd","expected_regex":"root:[^:]*:0:0:"}},
      "csp_validation_policy":{"external_server_required":False,"probe_origins":["http://127.0.0.1","http://localhost","http://example.invalid"],"execution_required":False,"confirm_policy_weakness_separately":True},
      "resource_context":c,
    }
    return "BUGTRACEAI ITEM-COGNITIVE PROMPT\n" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def prompt_metrics(text: str) -> Dict[str, Any]:
    chars=len(text)
    return {"chars":chars,"estimated_tokens":round(chars/4),"lines":text.count("\\n")+1}


AUTOMATED_TOOL_FREEDOM = "Podés elegir libremente solicitudes HTTP manuales o herramientas automatizadas disponibles en Kali cuando lo consideres más eficiente. No existe una política fija de herramientas."
