# Deployment plan

Production integration is intentionally staged to avoid disrupting active development work.

## Stage 0 - isolated prototype

Current state.

- Build and self-test on GamePC.
- No live GoGoMCP hooks.
- No MSI changes.
- No account/ACL changes.

## Stage 1 - decision-only integration

GoGoMCP asks Mutation Firewall to classify shell/process requests and path mutations.

- Critical raw destructive commands are refused.
- High-risk overwrite/clean operations require a structured broker path.
- Safe commands continue normally.
- Existing recycle-safe GoGoMCP behavior remains as a fallback.

This stage changes policy behavior but not Windows permissions.

## Stage 2 - broker service

Install Mutation Firewall as an independent Windows service outside the GoGoMCP tree.

- local-only IPC
- separate logs and policy
- watchdog health check
- recovery package on E:
- service must fail closed

## Stage 3 - OS containment

Run agent-facing execution under a dedicated restricted Windows identity.

The agent identity receives:

- read/execute access to Windows and installed toolchains
- full working rights only in explicit development workspaces and its own temp/profile areas
- no write/delete authority over Windows, Program Files, recovery roots, boot/storage administration, secrets, tunnel credentials, or drive roots

Project-root ACLs are tested first on a sacrificial workspace.

Do not switch the live GoGoMCP/DSH tree to the restricted identity until the test workspace passes build, Git, package-manager, compiler, and process tests.

## Stage 4 - both machines

After GamePC is proven:

- reproduce the policy/service on StreamingPC
- add machine-specific protected roots and workspaces
- peer-watch the service and watchdog
- keep quarantine local to each volume
- never share one writable quarantine between machines

## Promotion gate

Before production:

- self-test passes
- sacrificial delete/overwrite/restore passes
- drive-root test blocks
- Windows-root test blocks
- junction escape test blocks
- large-tree blast-radius test blocks
- compiler/package workflows still function in a test workspace
- GoGoMCP health remains normal
- no effect on unrelated Cloudflare tunnels
