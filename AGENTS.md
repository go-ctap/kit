# AGENTS.md

## Project
- `ctapkit` is a reusable CTAP/FIDO2 runtime library for the `go-ctap` application family.
- The root `ctapkit` package is the public runtime facade; this repository is not a CLI.
- Do not add terminal UX, renderers, prompts, spinners, command trees, or product-specific output.

## Boundaries
- Public runtime API belongs in `ctapkit`; DTOs in `model`; device/transport abstractions in `device` and `transport`.
- Sessions, operations, workflows, authenticator handles, caches, tokens, and secrets stay private under `internal/`.
- When behavior is unclear, read the package that owns the concern before changing it.

## Safety And Runtime
- Rely on `go-ctaphid` for per-command CTAP serialization.
- Use session workflow serialization only to prevent multi-step flows from interleaving on the same opened authenticator.
- Do not add process-wide or cross-process device leases; CTAPHID channel isolation owns multi-client transport coordination.
- Treat authenticator state as externally mutable between commands and handle resulting CTAP errors without assuming workflow-level atomicity.
- Public close/cancel/continue paths must release owned resources and tolerate duplicate or racing consumer calls.
- Never log, marshal, or expose `pinUvAuthToken`, PINs, reset phrases, or tokens.
- When taking ownership of caller-provided secret bytes, copy them and wipe the caller-owned buffer at that boundary.
- Mutating operations must support dry-run and explicit confirmation; destructive operations require strong confirmation semantics.

## API And Go
- Following Go formatting/style is critical: use `gofmt`/`goimports`, Google Go Style Guide, and Go Code Review Comments.
- Preserve semantic whitespace: separate logical phases with blank lines; keep `x, err := ...` cuddled with its `if err != nil`; do not cuddle unrelated statements, side effects, or final returns; keep tiny error pairs tight; do not wrap long lines only for arbitrary width.
- Do not add compatibility aliases or re-export wrappers for old layouts.
- Keep `New` minimal; add runtime configuration only when consumers truly need it.
- Prefer `go-ctap/ctaphid` helpers for HID/proxy discovery; authenticator opening belongs behind the runtime's private opener.
- Custom sentinel errors should include the `ctapkit: ` prefix, with small explicit runtime category mapping.
- Supported Go version: Go 1.26.x only. Keep `go.mod` aligned; do not add old-version shims.
- Keep file splits coarse and domain-shaped; keep hardware-dependent behavior out of default no-hardware tests.

## Verification
- Run `go test ./... -count=1` and `go vet ./...` before handoff; add `go test -race ./... -count=1` for runtime lifecycle/session changes.
