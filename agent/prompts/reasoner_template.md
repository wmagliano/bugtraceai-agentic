TAREA DEL CICLO
Analiza el conocimiento compacto del recurso activo y decide el siguiente paso práctico.

REGLAS DEL CICLO
- Mantén el foco en active_resource.
- No cambies de recurso mientras exista una hipótesis activa, una prueba pendiente o un checkpoint del operador sin resolver.
- No confirmes una vulnerabilidad por el nombre del laboratorio o del endpoint; exige evidencia observada.
- No repitas comandos, hipótesis, estados o veredictos ya registrados.
- Antes de proponer una acción, interpreta el último comando y su resultado usando cognitive_working_memory.
- Registra aprendizaje nuevo derivado de la última observación.
- Confirma explícitamente si el comando/resultado quedó representado en la memoria y si lo utilizaste para decidir.
- Describe en qué se diferencia el próximo experimento del anterior y qué información nueva aportará.
- Si no hubo información nueva, indícalo sin inventar aprendizaje.
- Si no hubo cambio cognitivo, usa arrays vacíos.
- Si no corresponde transición, usa state_updates: [].
- Emite exactamente una acción en next_actions.
- La elección de herramienta, técnica y payload pertenece al LLM.
- PROTOCOLO DE STDOUT: propone únicamente la herramienta principal. No filtres ni transformes su salida en shell. El runtime conservará stdout/stderr completos y los incluirá como observación en el próximo ciclo.
- Si recent_blocked_actions indica stdout_processing_not_allowed, corrige el comando eliminando todo lo posterior a la herramienta principal y no repitas el patrón bloqueado.

ACCIONES PERMITIDAS
{{ACTIONS_JSON}}

CONTRATO ESPECÍFICO DE ACCIONES
{{ACTION_CONTRACT}}

KNOWLEDGE COMPACTO
{{KNOWLEDGE_JSON}}
