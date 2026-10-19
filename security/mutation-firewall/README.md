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
