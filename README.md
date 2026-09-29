# BugTraceAI Agentic

> **v0.1.0-alpha — DVWA Research Release**

`bugtraceai-agentic` is a **working project name**. This repository publishes a reproducible Alpha snapshot of the BugTraceAI scientific research project: an experimental local-LLM agent architecture for autonomous cybersecurity analysis in a controlled laboratory.

**DVWA is the only target claimed as validated here.** Work on bWAPP and other environments belongs to the continuing generalization study and is not presented as a supported capability of this Alpha.

## Why this project exists

BugTraceAI investigates whether an LLM-driven agent can preserve a stable architecture while target, security level, knowledge context and experimental conditions change. The design separates reasoning from execution instead of embedding a vulnerability playbook directly into the agent.

## Release identity

| Item | Alpha value |
|---|---|
| Public release | `v0.1.0-alpha` |
| Scientific baseline | `v3.0.5b-r0-v2-repair` |
| Final Alpha patch | bounded contract-repair `action` type guard |
| Validated target | DVWA laboratory |
| MCP component | `kali_mcp-v2.5.6d-open` |
| License | Apache-2.0 |

Original baseline version markers are retained inside `agent/` for scientific traceability and should not be confused with the public release number.

## Architecture

The following visual overview summarizes the Alpha laboratory, major components, operating flow and research positioning. The technical diagram immediately below shows the architecture and component relationships in greater detail.

<p align="center">
  <img src="assets/bugtraceai-banner.png" alt="BugTraceAI Agentic — architecture, workflow and research laboratory overview" width="100%">
</p>

```mermaid
flowchart LR
    LLM[Local LLM<br/>192.168.0.9:8080] -->|reasoning| AGENT
    subgraph AGENT[BugTraceAI Agent]
      S[Scheduler] --> R[Reasoner]
      C[Config] --> R
      K[Cassette / RAG] --> R
      R --> D[Decision Contract]
      D --> E[Executor]
      M[State / Memory / Evidence] <--> R
    end
    E -->|MCP| KALI[Kali MCP<br/>192.168.0.34:9001]
    KALI -->|controlled execution| DVWA[DVWA Lab<br/>192.168.0.200:80]
```

- **Config** defines environment, access, restrictions, scope and experiment parameters.
- **Cassette/RAG** contributes contextual knowledge.
- **Reasoner** chooses the next action under a structured contract.
- **Executor/MCP** performs permitted execution.

A resource being observed does **not** automatically mean it is selected, analyzed or executed against.

## Reference laboratory

```text
Local LLM : 192.168.0.9:8080
DVWA      : 192.168.0.200:80
Kali MCP  : 192.168.0.34:9001
```

These values are deliberately visible because this Alpha prioritizes reproducibility over a polished installer.

## Inside a real BugTraceAI decision cycle

The following example is taken from a **real controlled DVWA LOW laboratory run**. Its purpose is not to present a password attack recipe, but to make the internal behavior of the agent observable: how a resource is selected, how a hypothesis is tested, how execution is constrained by the contract/MCP boundary, how evidence is returned to the Reasoner, and how the resource finally reaches a terminal state.

<p align="center">
  <img src="assets/bugtraceai-dvwa-bruteforce-flow.png" alt="BugTraceAI — controlled DVWA LOW brute-force hypothesis validation and agent decision cycle" width="100%">
</p>

### What the agent is doing, step by step

1. **Scheduler and resource budget — select work, do not execute blindly.**  
   The Scheduler selects the DVWA `/vulnerabilities/brute/` resource and assigns it a bounded resource budget. At this point the resource is `HYPOTHESIS_ACTIVE`: BugTraceAI has something to investigate, but that state is not itself a vulnerability verdict.

2. **Session Guard — verify the experimental preconditions.**  
   Before reasoning about the challenge, Session Guard confirms that the DVWA session is authenticated, that the effective security level is `LOW`, and that the session check is valid. This prevents the Reasoner from interpreting a login/session failure as evidence about the vulnerability under study.

3. **Reasoner — establish a falsifiable contrast.**  
   From the previous observation, the LLM identifies the explicit failure response `Username and/or password incorrect.`. It records that observation as evidence and states what is still missing: observing the response produced by a valid credential so that failure and success can be distinguished.

4. **Decision Contract — turn reasoning into one bounded action.**  
   The Reasoner emits a structured `propose_mcp_command` action. The decision includes a reason, risk level, approval requirement and an `expected_evidence` matcher. The important architectural point is that reasoning does not directly execute against DVWA; it produces an action that must satisfy the agent contract.

5. **Executor + Kali MCP — validate and perform the controlled test.**  
   The proposed action is validated by the MCP contract and, in autonomous laboratory mode, approved for execution. Kali MCP performs the controlled request using the existing DVWA cookie jar. The resulting stdout/stderr and execution metadata are returned to BugTraceAI and stored as an observation.

6. **Evidence and cognitive memory — reason from the result, not from the intention.**  
   On the next cycle the Reasoner consumes the actual saved result. It observes the explicit success response `Welcome to the password protected area admin`, contrasts it with the previously learned failure response, records the fact/evidence with high confidence, and marks the hypothesis as supported.

7. **State transition — evidence changes the resource state.**  
   With the contrast experimentally observed, the resource moves to `CONFIRMED`. The agent records why the transition occurred rather than treating successful command execution alone as proof of a vulnerability.

8. **Operator checkpoint and completion — separate confirmation from workflow closure.**  
   BugTraceAI asks whether the operator wants to document, continue controlled exploitation, collect more non-destructive evidence, perform deeper analysis, or mark the case inconclusive. In the autonomous research run, the configured checkpoint selects close/document, so the resource transitions from `CONFIRMED` to `COMPLETED` and the Scheduler releases the Analysis Item.

The observed lifecycle in this example is therefore:

```text
HYPOTHESIS_ACTIVE
        │
        ▼
     TESTING
        │
        │  evidence: failure/success response contrast
        ▼
    CONFIRMED
        │
        │  operator/autonomous checkpoint
        ▼
    COMPLETED
```

> **Scientific interpretation.** This trace demonstrates the agent's hypothesis/evidence workflow on the intentionally vulnerable DVWA LOW challenge. The shown run validates the brute-force hypothesis by contrasting a known invalid credential with the known valid laboratory credential (`admin/password`). It should **not** be interpreted as evidence that this particular trace performed exhaustive password enumeration. The research value of the example is the observable decision architecture: selection → precondition check → hypothesis → contracted action → controlled execution → evidence → state transition → closure.

## Hardware used in the research laboratory

The DVWA Alpha experiments were developed and exercised on a local workstation designed to keep the LLM and research data under operator control.

| Component | Research laboratory |
|---|---|
| Platform | X99-T8D workstation |
| CPU | 2 × Intel Xeon E5-2678 v3 |
| System RAM | 256 GB |
| GPU | NVIDIA GeForce RTX 3090 |
| VRAM | 24 GB |
| LLM | BugTraceAI-CORE-Ultra-SFT Q6_K |
| Inference | llama.cpp, GPU offload |

The large system-memory capacity is part of the research workstation and should **not** be interpreted as a requirement for BugTraceAI.

### Practical minimum recommended

For reproducing this Alpha with the supplied 8B-class Q6_K local model, a practical starting point is:

| Component | Recommended minimum |
|---|---|
| CPU | Modern x86-64 CPU, approximately 8 threads or more |
| System RAM | 32 GB |
| GPU | NVIDIA GPU with approximately 16 GB VRAM |
| Storage | 30 GB free space for model, project and experiment outputs |
| LLM runtime | llama.cpp-compatible local inference |
| Network | Connectivity between Agent, Kali MCP, LLM and isolated DVWA hosts |

**24 GB VRAM is preferred** for a setup closer to the reference laboratory and provides more headroom for context and GPU offload. CPU-only or lower-VRAM configurations may be possible with different offload/context settings, but they are expected to be substantially slower and are not the configuration characterized by this research.

These minimum values are **practical recommendations, not experimentally established lower bounds**. Performance depends on model quantization, context size, GPU offload, batch settings and experiment workload.

## Reference local LLM

```bash
~/llama.cpp/build/bin/llama-server \
  -m ~/llm/models/offensive/BugTraceAI-CORE-Ultra-SFT-Q6_K.gguf \
  --host 0.0.0.0 --port 8080 --ctx-size 16384 \
  --threads 8 --threads-http 4 --n-gpu-layers 99 \
  --batch-size 512 --parallel 1 --flash-attn on --reasoning off
```

This is a reference experiment configuration, not a universal hardware/model requirement.

## Repository layout

```text
agent/   Scientific DVWA baseline and cassettes
mcp/     Audited Kali MCP v2.5.6d-open and benign lab assets
docs/    Research, architecture, setup and limitations
```

Generated logs, reports, runtime projects, caches, compiled Python files and the experimental bWAPP configuration are deliberately excluded.

## Contract safety

The Reasoner uses structured actions and validation before execution. The final bounded repair can fill missing required fields only; it cannot silently replace the chosen action or overwrite supplied fields, and repaired output must pass normal validation.

The DVWA policy preserves the authenticated cookie-jar model and constrains Upload testing to benign research artifacts.

## Getting started

1. Build an isolated DVWA laboratory.
2. Prepare the Kali MCP host and supplied MCP component.
3. Start the local LLM endpoint.
4. Review reference IPs and DVWA profile in `agent/config/` and `agent/config.env`; explicitly verify the effective DVWA `authentication.security` level before every run.
5. Initialize the agent and run the experiment using the baseline scripts.

This release intentionally does not hide target-specific settings behind a new installer.

**Operator documentation:** [Installation & Operations](docs/installation-and-operations.md) · [Basic Configuration](docs/basic-configuration.md) · [Configuration reference](docs/configuration.md) · [Reference lab](docs/reference-lab.md).

## Limitations

- Alpha research software; interfaces and project name may change.
- DVWA is the supported/validated target of this release.
- Some client-side/browser-dependent cases require operator validation.
- Resolution depends on local model, context, budgets and experimental configuration.
- bWAPP, Juice Shop and WebGoat are roadmap targets, not capabilities claimed by this release.

## Legal and ethical use disclaimer

BugTraceAI is an experimental vulnerability-analysis research project intended for **controlled laboratory environments, cybersecurity research, education, and systems for which the operator has explicit authorization to perform security testing**.

**Do not use BugTraceAI to scan, analyze, test, exploit, or otherwise interact with systems, networks, applications, or infrastructure without the owner's explicit permission.** The reference configuration and supplied workflows are designed for an intentionally vulnerable, isolated DVWA laboratory.

The end user is solely responsible for ensuring that every use of this software complies with applicable laws, regulations, organizational policies, contractual obligations, and authorization boundaries. The project authors and contributors do not authorize use against third-party systems and are not responsible for misuse, unauthorized activity, damage, service disruption, data loss, or legal consequences resulting from the user's operation of the software.

By using BugTraceAI, the operator accepts responsibility for the targets selected, the permissions obtained, the commands executed, and the resulting effects. When in doubt about authorization or scope, **do not run the analyzer against the target**.

This disclaimer complements, and does not replace, the terms of the Apache License 2.0.

## Documentation

[Installation & Operations](docs/installation-and-operations.md) · [Basic Configuration](docs/basic-configuration.md) · [Project overview](docs/project-overview.md) · [Methodology](docs/scientific-methodology.md) · [Architecture](docs/architecture.md) · [Reference lab](docs/reference-lab.md) · [Configuration](docs/configuration.md) · [Kali MCP](docs/kali-mcp.md) · [Roadmap](docs/limitations-and-roadmap.md) · [Source integrity](docs/source-integrity.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
