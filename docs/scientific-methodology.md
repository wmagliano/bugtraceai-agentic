# Scientific methodology

## Why repeated runs matter

An agentic system can appear successful from a single favorable trajectory. BugTraceAI therefore treats repeated cycles, state transitions, evidence, inconclusive outcomes and operator-validation requirements as experimental data.

## Experimental variables

The DVWA research line varied factors such as security level, cycle/iteration budgets, blacklist policy, Cassette/RAG composition and Reasoner settings while attempting to preserve the architectural boundaries.

## Interpretation model

The project distinguishes four concepts that should not be collapsed: a resource can be **observed/referenced**, **selected**, **analyzed**, and an action can be **executed** through MCP.

This distinction is particularly important when evaluating blacklist and scope behavior. A URL appearing in discovered content is not evidence that the agent spent LLM/GPU budget analyzing it or executed a command against it.

## Evidence discipline

Cassette knowledge, model confidence and a plausible attack pattern are not sufficient to establish a finding. Evidence must come from the active resource and experiment.

## Claims made by this release

The release represents the project's closed DVWA research baseline. It does not use ongoing bWAPP experiments as evidence of general-purpose support. A later target is a new experimental condition and must be evaluated before changing the supported-scope claim.
