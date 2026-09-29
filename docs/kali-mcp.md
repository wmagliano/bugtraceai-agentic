# Kali MCP v2.5.6d-open

The public Alpha uses the separately supplied stable MCP package under `mcp/kali_mcp-v2.5.6d-open/`.

The MCP is the controlled execution boundary between BugTraceAI decisions and Kali tooling. It also owns the DVWA session cookie on the Kali host.

The package contains the MCP server, bootstrap/validation scripts, DVWA login helper, requirements, self-tests and controlled assets used by DVWA validation profiles.

Files under `assets/` are intentionally benign laboratory artifacts. Several filenames emulate upload-extension edge cases, but their purpose is controlled DVWA validation rather than deployment of a persistent webshell.

The server includes scope checks and blocks destructive operations. This is part of the architecture: an open research MCP does not mean unrestricted execution.

Review `requirements.txt`, `bootstrap_mcp.sh`, `install_kali_assets.sh`, `validate_bugtraceai_mcp.sh` and the version changelog before starting the service. Do not expose the MCP directly to untrusted networks.
