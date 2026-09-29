# R0-v2 changes

- Runtime directories cleaned for distribution; `data/knowledge.json` bootstraps as `{}`.
- Historical run/reset wrappers and historical documentation removed from the distribution copy.
- Added `config/sites/dvwa.json`, `config/sites/bwapp.json`, and active `config/site.json`.
- Added `setup-web.sh` for deterministic target profile generation.
- URL and vulnerability blacklists are now profile-driven with R0-compatible fallback defaults.
- Added generic `web-vulnerabilities-2026` adaptive RAG cassette.
- Active entrypoints default to `config/site.json`.
- No browser, exploitation, state-machine, Reasoner, Executor or Scheduler capability expansion is introduced by this refactor.
