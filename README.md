# ctapkit

Reusable CTAP/FIDO2 runtime core for the `go-ctap` application family.

The current Go module is:

```go
module github.com/go-ctap/kit
```

The root package is imported as:

```go
import "github.com/go-ctap/kit"
import "github.com/go-ctap/kit/model"
import "github.com/go-ctap/kit/transport"
```

## What This Is

`ctapkit` provides the shared runtime boundary for applications that need to discover, inspect, and safely control local FIDO2 authenticators. It is designed for CLI, GUI, and TUI consumers that want the same device/session/operation semantics without duplicating CTAP safety logic.

This repository does not own terminal UX, command parsing, output rendering, MDS presentation, release packaging, or product-specific workflows. Those live in consumer applications.

## Package Layout

- `ctapkit`: public runtime facade.
- `model`: public operation, event, interaction, and session DTOs.
- `model/failure`: stable machine-readable failure codes and transport-safe snapshots.
- `model/config`: authenticator config DTOs and reports.
- `model/credentials`: credential DTOs, previews, and reports.
- `model/largeblobs`: large-blob DTOs, previews, and reports.
- `model/report`: shared report DTOs used across model domains.
- `model/safety`: shared safety/confirmation DTOs.
- `transport`: HID and Windows proxy transport boundary.
- `internal/device`: stable device identity derived from discovery descriptors.
- `internal/runtime`: event, interaction, and token policies.
- `internal/session`: opened-session core, lifecycle, serialization, and cache boundary.
- `internal/workflow`: operation dispatch and domain workflow bodies over an explicit execution environment.

## Session Flow

A consumer should generally do this:

1. Convert UI or CLI input into a typed `model.Operation`.
2. Discover devices with `ctapkit.DiscoverDevices`.
3. Pick one returned `ctapkit.Device` handle and open it with `ctapkit.OpenSession`.
4. Run one typed operation synchronously with `Session.Run`.
5. Clean up with `Session.Close`.

`Session.Run` returns the typed `model.OperationResult` directly. Consumers that need non-blocking UI can call it from their own goroutine or task. Progress and UI updates are delivered through the `model.EventSink` attached with `ctapkit.WithEventSink`; PIN, user-verification, touch, and confirm participation is delivered through `model.InteractionHandler`.
Interaction requests and operation events contain only their prompt or event payload; consumers should correlate session-specific work through the `*ctapkit.Session` handle and their own event sink ownership.

Public failures use stable codes, optional safe interpolation parameters, and
exact CTAP provenance. See the [machine-readable error
contract](docs/error-contract.md).

Verification defaults to UV when the authenticator supports it, with PIN fallback when CTAP reports a fallback condition. A consumer that wants to offer "use PIN" before starting work can pass `ctapkit.WithVerificationFlow(model.VerificationFlowPIN)` to `Session.Run`. User-verification interactions are pre-command prompt and cancel points; the authenticator remains authoritative for whether UV actually succeeds.

Core operations are intentionally UI-neutral. PIN prompts, user verification messages, spinners, progress bars, tables, JSON/YAML formatting, and GUI/TUI event presentation belong to the consumer.

MDS lookup is exposed as a root facade helper rather than a session operation:

```go
metadata, err := ctapkit.LookupMDS(ctx, inspect.Result.Info.AAGUID)
```

The runtime fetches and verifies the FIDO MDS3 blob, indexes entries by AAGUID,
and caches the verified response in memory and on disk under the user cache
directory. Disk cache entries are verified again before use. Consumers own any
MDS presentation or policy decisions.

## Safety Model

- Per-session workflow serialization prevents multi-step flows on the same opened authenticator from interleaving.
- CTAPHID channel isolation and per-command serialization allow independent clients to share an authenticator; external state changes remain possible between commands and must be handled as normal runtime errors.
- `pinUvAuthToken` values and other runtime-owned secrets are never exposed through public results. Root `model` PIN operations omit PINs when marshaled; the Wails-oriented `service` request DTOs keep typed PIN fields in JSON, so adapters and clients must redact them and must not log or persist serialized requests.
- Mutating operations preserve dry-run and confirmation semantics.
- Destructive flows such as reset, credential deletion, and large-blob deletion require explicit confirmation.
- Factory reset must be executed shortly after authenticator power-up on many authenticators; consumers should collect any strong UI confirmation before reconnecting and then run a confirmed reset promptly.

## Verification

Run the default checks with:

```powershell
go test ./... -count=1
go vet ./...
```

For lifecycle, session, interaction, or synchronization changes, also run:

```powershell
go test -race ./... -count=1
```
