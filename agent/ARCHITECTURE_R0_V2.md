# BugTraceAI v3.0.5b-r0-v2 — Web configuration boundary

## Configurable per web target
- base URL / target host
- authentication profile and cookies
- URL exclusions and deferred vulnerability paths
- site-specific session data
- cassette selection

## Core / documented invariants
- Scheduler, Analysis Queue, Reasoner, Executor, state machine and verdict semantics are core.
- Vulnerability analysis is primary; exploitation is secondary and must not redefine a confirmed vulnerability verdict.
- Browser/DOM/JavaScript-dependent confirmation is outside the current autonomous capability and may require operator validation.
- External callback/C2-style dependencies are outside the current local architecture unless explicitly provided by the environment.
- RAG/cassette knowledge is context, never evidence.

## Profiles
`./setup-web.sh dvwa` and `./setup-web.sh bwapp` generate `config/site.json`.
DVWA is the R0-v2 regression target. bWAPP configuration is prepared for the next adaptation phase; its authentication/session adapter must be validated before claiming functional parity.
