# BugTraceAI-Agent v1.4 - Kali Session + Base64 Transport

Versión consolidada práctica de V1.4.

Arquitectura:

```text
Ubuntu
  reasoner.py
  reasoner_llm.py
  executor_mcp.py
  data/knowledge.json
        |
        | POST /tools/exec
        v
Kali MCP
  /opt/bugtraceai-mcp/bugtraceai_dvwa_login.sh
  curl / sqlmap / ffuf / nmap / ...
  /tmp/bugtraceai-session/dvwa_cookie.txt
        |
        v
DVWA
```

Principios:

- El LLM decide.
- Ubuntu coordina y guarda memoria.
- Kali ejecuta todo lo que toca al objetivo.
- La cookie de DVWA vive en Kali, no en Ubuntu.
- El transporte Ubuntu <-> Kali usa `command_b64`, `stdout_b64`, `stderr_b64`.
- Base64 es solo transporte; el LLM sigue viendo comandos normales y contexto decodificado.

---

## 1) En Kali: instalar helper de sesión

Desde el ZIP, copiar:

```bash
sudo mkdir -p /opt/bugtraceai-mcp
sudo cp kali_mcp/bugtraceai_dvwa_login.sh /opt/bugtraceai-mcp/bugtraceai_dvwa_login.sh
sudo chmod +x /opt/bugtraceai-mcp/bugtraceai_dvwa_login.sh
sudo ln -sf /opt/bugtraceai-mcp/bugtraceai_dvwa_login.sh /usr/local/bin/bugtraceai_dvwa_login
```

Probar en Kali:

```bash
bugtraceai_dvwa_login \
  http://192.168.0.200 \
  admin \
  password \
  low \
  /tmp/bugtraceai-session/dvwa_cookie.txt

curl -ksS -b /tmp/bugtraceai-session/dvwa_cookie.txt \
  http://192.168.0.200/index.php | grep -iE 'dvwa|logout|vulnerabilities'
```

---

## 2) En Kali: actualizar MCP

Aplicar lo indicado en:

```text
MCP_SERVER_PATCH.md
```

El endpoint `/tools/exec` debe aceptar:

```json
{"command_b64":"...","timeout":900}
```

Y devolver:

```json
{"ok":true,"returncode":0,"stdout_b64":"...","stderr_b64":"..."}
```

---

## 3) En Ubuntu: probar BugTraceAI

```bash
python3 selftest_v14.py
./reset_v14_lab.sh
./run_v14_cycle.sh 5
```

Durante `reset_v14_lab.sh` ahora ocurre:

```text
run_login   -> ejecutado en Kali vía MCP
run_interior -> ejecutado en Kali vía MCP usando cookie local de Kali
```

---

## 4) Archivos importantes

```text
executor_mcp.py                 executor único
reasoner.py                     fallback conservador
reasoner_llm.py                 llamada al LLM
kali_mcp/bugtraceai_dvwa_login.sh helper de login en Kali
MCP_SERVER_PATCH.md             instrucciones para MCP Kali
data/knowledge.json             memoria operativa
logs/pages/                     HTML/headers capturados
```

---

## 5) Prueba esperada

Después del reset, revisar:

```bash
cat data/knowledge.json | jq '.session'
cat data/knowledge.json | jq '.mcp_interior_observations[-1]'
cat data/knowledge.json | jq '.candidate_urls'
ls -lh logs/pages/
```

La sesión debería indicar:

```json
{
  "authenticated": true,
  "cookie_location": "kali",
  "cookie_jar": "/tmp/bugtraceai-session/dvwa_cookie.txt"
}
```


## Nota r2 - Login en Kali antes del LLM

Para esta variante, el login DVWA debe quedar inicializado en Kali antes de consultar al LLM.
El script `reset_v14_lab.sh` ejecuta `run_login` vía MCP y se detiene si no queda confirmado.

En Kali, instalar primero:

```bash
cd kali_mcp
./install_kali_assets.sh
```

Prueba manual en Kali:

```bash
bugtraceai_dvwa_login \
  http://192.168.0.200 admin password low \
  /tmp/bugtraceai-session/dvwa_cookie.txt

curl -ksS -b /tmp/bugtraceai-session/dvwa_cookie.txt \
  http://192.168.0.200/index.php | grep -iE 'logout|vulnerabilities|dvwa'
```

## Nota R4 - MCP Kali

Para esta versión, el MCP de Kali debe permitir `bugtraceai_dvwa_login`.
El archivo parcheado está incluido en `kali_mcp/kali_mcp_server.py`.
Ver `MCP_SERVER_PATCH.md`.

## BugTraceAI v1.8 — Scheduler determinístico

Inicialización limpia del laboratorio:

```bash
./reset_v14_lab.sh
```

Ejecución autónoma de hasta 100 ciclos:

```bash
./run_v18_scheduler.sh
```

Estado de la cola:

```bash
python3 resource_scheduler.py status
```

Reabrir explícitamente un recurso terminal:

```bash
python3 resource_scheduler.py reopen http://192.168.0.200/vulnerabilities/brute/
```

Marcar manualmente un recurso:

```bash
python3 resource_scheduler.py mark URL INCONCLUSIVE --reason "Motivo del operador"
```

## BugTraceAI v1.8.1

### Política fija para cambios de contraseña

En cualquier ataque que modifique una contraseña, el runtime impone:

```text
usuario: admin
contraseña nueva: password
confirmación: password
```

Aunque el LLM proponga otros valores, el executor normaliza el comando antes de mostrarlo y ejecutarlo.

### Aprobación MCP

Las preguntas de aprobación ahora aceptan:

```text
YES   Ejecutar la acción MCP.
NO    Rechazar solamente la acción actual y mantener el recurso activo.
NEXT  Cerrar el análisis/explotación, marcar el recurso COMPLETED y pasar al siguiente.
```

Pruebas locales:

```bash
python3 selftest_v180.py
python3 selftest_v181.py
```

## v1.8.2.1 — ejecución autónoma sin loop de cierre

```bash
./reset_v14_lab.sh
./run_v182_autonomous.sh 500
```

El modo autónomo cierra directamente un recurso confirmado como `COMPLETED`, libera `active_resource` y continúa con la siguiente URL. El LLM no puede navegar a una URL distinta del recurso activo.
