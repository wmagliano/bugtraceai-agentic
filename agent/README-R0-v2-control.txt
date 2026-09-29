R0-v2 — control científico de configuración/contexto

Objetivo:
- No modificar CORE, Reasoner, contrato, Scheduler, Discovery, Executor ni MCP.
- Reutilizar la configuración y el cassette funcionales de R0-FINAL-C1-FIX.
- Cambiar únicamente los nombres/identificadores requeridos por R0-v2:
    config/dvwa.json       -> config/site.json
    cassette dvwa-lab      -> web-vulnerabilities-2026
- Corregir sólo la etiqueta contradictoria "DVWA Low" a "DVWA High" porque authentication.security=high.

Esta variante sirve como control/ablación: si desaparecen los missing_required_field/SAFE STOP,
la evidencia favorece que la regresión estaba inducida por el contexto/configuración/cassette y no por el CORE.

No se incorporó en esta prueba el cassette genérico nuevo de R0-v2, para no mezclar variables.
