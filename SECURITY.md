# Security policy

BugTraceAI is offensive-security research software intended for controlled, explicitly authorized laboratories.

## Safe deployment

- Run DVWA on an isolated lab network.
- Do not expose Kali MCP to untrusted networks.
- Review target/scope configuration before every experiment.
- Treat generated logs, cookies and reports as potentially sensitive and keep them out of source control.
- Do not reuse real credentials in DVWA profiles.

## Authorized use

Do not use BugTraceAI against systems without explicit authorization. The presence of a URL in a configuration file or discovered page is not authorization to test it.
