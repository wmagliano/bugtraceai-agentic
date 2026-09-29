# Limitations and roadmap

## Current boundary

`v0.1.0-alpha` publishes the DVWA research baseline. It is a scientific artifact, not a finished autonomous pentesting product.

## Known limitations

- Target-specific assumptions remain visible in configuration and controlled lab policies.
- The local LLM is an experimental variable; different models can change resolution and contract adherence.
- Browser/client-side behavior is not generally modeled by a full browser automation architecture in this baseline.
- Iteration budgets, RAG context and blacklists materially affect runtime and GPU cost.
- Authentication/session handling is proven for the DVWA laboratory pattern, not arbitrary authentication architectures.
- Generated experiment reports and the in-progress bWAPP configuration are deliberately omitted.

## Generalization roadmap

Candidate research environments include bWAPP, OWASP Juice Shop and WebGoat. The goal is to determine whether new environments require only configuration/context changes or expose missing architectural primitives.

A future target should not be advertised as supported merely because the agent can reach it. Support should follow a closed validation cycle.
