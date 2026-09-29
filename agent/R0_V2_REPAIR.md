# BugTraceAI v3.0.5b-r0-v2-repair

Experimental CR1 subversion derived directly from the supplied R0-v2 DVWA baseline.

## Scope
- Adds one bounded LLM contract-repair attempt only when `next_actions[0]` is missing required fields.
- Existing action and existing fields are immutable during repair.
- The repair output may contain only the missing fields.
- The normal `validate_decision_schema()` remains authoritative and revalidates the merged decision.
- Policy/semantic/type/URL/placeholder and other rejection classes are not repaired.
- If repair fails or the repaired decision still fails validation, the pre-existing SAFE STOP path is preserved.
- No Scheduler, Discovery, Executor, MCP, state-machine, vulnerability logic, or tool-selection code was changed.

## Telemetry
Look for `[CONTRACT REPAIR]` in console and `CONTRACT_REPAIR_*` / `contract_repair_*` events in existing diagnostic logs.
