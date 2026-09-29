# Project overview

## Research question

BugTraceAI studies whether an LLM-centered security agent can keep **reasoning, state, contextual knowledge and tool execution as separable components** while moving through increasingly different laboratory targets.

The project is not designed around a fixed vulnerability scanner pipeline. The LLM is expected to interpret observations and evidence, while deterministic components constrain what can be selected, executed, remembered and reported.

## Scope of v0.1.0-alpha

This release freezes the DVWA research baseline. Its purpose is reproducibility and architectural inspection. The code under `agent/` derives from `v3.0.5b-r0-v2-repair`; the public Alpha applies only the final defensive type check in the bounded contract-repair path of `reasoner_llm.py`.

The Kali execution boundary is published separately under `mcp/kali_mcp-v2.5.6d-open/` so that the stable MCP is not confused with historical copies embedded in older agent bundles.

## Design goals

1. Preserve a cognitive agent rather than convert the project into a hardcoded scanner.
2. Keep execution behind an explicit MCP boundary.
3. Make configuration, knowledge and reasoning separate concerns.
4. Preserve evidence and state so conclusions can be audited.
5. Fail safely when model output violates the action contract.
6. Measure behavior over repeated cycles rather than judge the system from one successful demonstration.

## Public Alpha versus ongoing research

The public Alpha is deliberately narrower than the complete research workspace. Experimental bWAPP configuration and generated experiment outputs are not included. Generalization results should be evaluated independently before being promoted into a later release.
