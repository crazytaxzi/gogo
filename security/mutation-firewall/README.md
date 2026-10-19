# Sentionce Mutation Firewall

Deterministic safety broker for AI-operated Windows development systems.

## Goal

Allow autonomous agents to build, edit, test, install dependencies, and coordinate while making catastrophic filesystem destruction difficult or structurally unavailable.

This project does **not** depend on an LLM.

## Current prototype

The prototype is intentionally isolated from the live GoGoMCP runtime.

Implemented:

- canonical absolute-path resolution
- immutable drive roots
- protected roots and exact protected paths
- reparse-point / junction / symlink rejection
- file, directory, and byte blast-radius limits
- same-volume quarantine instead of permanent deletion
- version-preserving replacement
- destination-preserving move
- quarantine manifests
- SHA-256 integrity for quarantined files
- restore from quarantine
- JSONL audit log
- command risk classification for common destructive Windows, Git, Docker, sync, archive, scripting, and filesystem API operations
- regression for the harmless `nvidia-smi --format=...` false positive
- built-in self-test

Current self-test: 15/15 passing.

## Important boundary

This prototype is not yet a complete OS sandbox. A process that still runs with unrestricted user/admin rights can bypass a broker by directly using operating-system APIs.

The production design therefore has two layers:

1. Mutation Firewall broker for reversible mutation and policy decisions.
2. Restricted agent execution identity / workspace ACL boundary so arbitrary agent code cannot bypass the broker to damage system roots.

Do not claim full containment until layer 2 is deployed and tested.

## Local paths

Source and recovery material:

`E:\SentionceRecovery\MutationFirewall`

Self-contained executable:

`E:\SentionceRecovery\MutationFirewall\publish\SentionceMutationFirewall.exe`

C-drive quarantine:

`C:\SentionceQuarantine`

E-drive quarantine:

`E:\SentionceRecovery\Quarantine`

## Safety invariants

- Never permanently delete through the broker.
- Never mutate a drive root.
- Never mutate a protected recovery/system root.
- Never follow a reparse point during a mutation.
- Never silently downgrade to permanent deletion when quarantine fails.
- Overwrite means preserve-old-then-replace.
- Restore verifies quarantine provenance and file hash when available.
- Large mutations fail closed.


## Checkpoint: 2026-10-18

Verified on GamePC:

- engine build: 0 warnings, 0 errors
- engine self-test: 15/15 passing
- self-contained win-x64 engine published
- SHA-256 of current published engine: `1658535e07dcce1a8a2af75afa0e2c0a44a0e09a1ee107d0825454ddba15725f`
- real sacrificial overwrite preserved the original in quarantine
- real sacrificial file quarantine preserved content and manifest
- real whole-directory quarantine passed
- independent named-pipe broker service builds with 0 warnings/errors
- broker console-mode named-pipe request passed
- broker-mediated sacrificial quarantine passed
- broker test process was stopped after testing
- staged GoGoMCP 0.5.0 integration passed OAuth + 56-tool smoke test on random non-production ports
- staged integration verified harmless `--format` is allowed
- staged integration verified overwrite-capable shell commands are broker-gated
- staged integration verified writes beneath `C:\Windows` are blocked
- staged integration verified file.delete uses quarantine semantics
- staged integration verified file.write preserves the prior version

Production state at this checkpoint:

- live GoGoMCP has NOT been replaced with the staged integration
- Mutation Firewall service has NOT been installed
- no Windows account/ACL changes have been made
- StreamingPC/MSI has NOT been modified by this work
- the current work is isolated under `E:\SentionceRecovery\MutationFirewall`
- GitHub safety branch: `safety/mutation-firewall-v0`

Remaining promotion gates:

- GitHub-hosted integration CI result
- junction/reparse escape regression: PASS on GamePC
- oversized-tree blast-radius regression: PASS at 502 files against 500-file ceiling
- named-pipe ACL tightening before privileged service deployment
- sacrificial restricted Windows identity/workspace test
- compiler/package-manager/dev workflow compatibility under restricted identity
- watchdog service-health integration
- GamePC production canary period
- only then reproduce the proven design on StreamingPC
