GoMCP Rebuilt Recovery Package

Canonical runtime: mcp/rebuilt/
One-click entry point: dist/GoMCP-OneClick.cmd
Installer implementation: install/Install-GoMCP.ps1

The installer downloads the canonical source, syntax-checks it before replacing files, preserves surviving state/config, recreates the scheduled task, requires localhost:8882 health with exactly 56 tools, and verifies gamepc-mcp.sentionce.net OAuth resource metadata.

Secrets are machine-local and are never stored in this repository.
