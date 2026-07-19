# go-ctap/kit

[![Go](https://github.com/go-ctap/kit/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/kit/actions/workflows/go.yml)

Reusable CTAP/FIDO2 runtime core for the `go-ctap` application family.

The runtime currently targets `github.com/go-ctap/ctap` v0.31.0 and exposes the
CTAP 2.3 operation model without legacy API aliases.

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

`ctapkit` provides the shared runtime boundary for applications that need to discover, inspect, and safely control local FIDO2 authenticators. It is designed for CLI, GUI, and TUI consumers that want the same device/authenticator/operation semantics without duplicating CTAP safety logic.

This repository does not own terminal UX, command parsing, output rendering, MDS presentation, release packaging, or product-specific workflows. Those live in consumer applications.

## Package Layout

- `ctapkit`: public runtime facade.
- `model`: public operation, event, and interaction DTOs.
- `model/failure`: stable machine-readable failure codes and transport-safe snapshots.
- `model/config`: authenticator config DTOs and reports.
- `model/credentials`: credential DTOs, previews, and reports.
- `model/largeblobs`: large-blob DTOs, previews, and reports.
- `model/report`: shared report DTOs used across model domains.
- `model/safety`: shared safety/confirmation DTOs.
- `transport`: HID and Windows proxy transport boundary.
- `internal/device`: runtime attachment fingerprints derived from transport descriptors.
- `internal/runtime`: event, interaction, and token policies.
- `internal/workflow`: operation dispatch and domain workflow bodies over an explicit execution environment.

## Authenticator Flow

A consumer should generally do this:

1. Convert UI or CLI input into the typed `model` input for the operation.
2. Discover devices with `ctapkit.DiscoverDevices`.
3. Pick one returned `ctapkit.Device` handle and open it with `ctapkit.OpenAuthenticator`.
4. Call the corresponding typed `Authenticator` method synchronously.
5. Close the authenticator when the selected device changes or the application exits.

`Authenticator` is the single long-lived runtime entity for an opened transport channel. It owns close/cancel behavior, whole-operation serialization, and one reusable `pinUvAuthToken`. It does not cache credential inventories, configuration reports, or large-blob reports; those values are read from the authenticator for every operation because device state can be changed by another channel between commands.

Each operation method returns a pointer to its concrete output type. A nil output means execution stopped before a workflow result existed; a non-nil output can carry a partial preview or result together with an error. For example, `Authenticator.ListCredentials` returns `*model.CredentialsOutput`, while `Authenticator.DeleteCredential` accepts `model.DeleteCredentialOperation` and returns `*model.CredentialDeleteOutput`. Consumers that need non-blocking UI can call these methods from their own goroutine or task. Progress and UI updates are delivered through the `model.EventSink` attached with `ctapkit.WithEventSink`; PIN, user-verification, touch, and confirm participation is delivered through `model.InteractionHandler`.
Interaction requests and operation events contain only their prompt or event payload; consumers should correlate work through the `*ctapkit.Authenticator` handle and their own event sink ownership.

Public failures use stable codes, optional safe interpolation parameters, and
exact CTAP provenance. See the [machine-readable error
contract](docs/error-contract.md).

Verification defaults to UV when the authenticator supports it, with PIN fallback when CTAP reports a fallback condition. A consumer that wants to offer "use PIN" before starting work can pass `ctapkit.WithVerificationFlow(model.VerificationFlowPIN)` to the typed operation method. User-verification interactions are pre-command prompt and cancel points; the authenticator remains authoritative for whether UV actually succeeds.

Core operations are intentionally UI-neutral. PIN prompts, user verification messages, spinners, progress bars, tables, JSON/YAML formatting, and GUI/TUI event presentation belong to the consumer.

MDS lookup is exposed as a root facade helper rather than an authenticator operation:

```go
metadata, err := ctapkit.LookupMDS(ctx, inspect.Result.Info.AAGUID)
```

The runtime fetches and verifies the FIDO MDS3 blob, indexes entries by AAGUID,
and caches the verified response in memory and on disk under the user cache
directory. Disk cache entries are verified again before use. Consumers own any
MDS presentation or policy decisions. A disk entry that cannot currently be
verified is retained for a later retry but is never returned as verified data.

## CTAP 2.3 Runtime Surface

- `model.InspectResult.Info` embeds `protocol.AuthenticatorGetInfoResponse`, so
  get-info fields and types track `ctap` directly; the kit only adds the UV
  modality label and conformance report.
- `model.CredentialStoreStateOperation` reads the persistent credential-store
  identifiers with a standalone `pcmr` token. The result contains lowercase
  hexadecimal identifiers and must be treated as sensitive.
- `model.EnableLongTouchForResetOperation` supports preview, dry-run, and
  confirmation before enabling the reset gesture requirement.
- `model.SetMinPINLengthOperation` mirrors the upstream config parameters:
  `NewMinPINLength` is optional, while RP-ID and boolean fields use their zero
  values when omitted.
- WebAuthn make-credential and get-assertion operations delegate direct and
  legacy `largeBlob` processing to `ctap`. A non-nil get-assertion
  `largeBlob.write`, including an empty blob, requires confirmation. The
  existing `largeBlobs.*` operations remain the explicit legacy-array
  management API.
- WebAuthn extension results preserve present-empty large blobs, explicit false
  `written`/`thirdPartyPayment` values, and make-credential `supported` output.

## Safety Model

- Per-authenticator workflow serialization prevents multi-step flows on the same opened channel from interleaving.
- CTAPHID channel isolation and per-command serialization allow independent clients to share an authenticator; external state changes remain possible between commands and must be handled as normal runtime errors.
- `pinUvAuthToken` values and other runtime-owned secrets are never exposed through public results. Root `model` PIN operations omit PINs when marshaled; consumer-owned transport DTOs may expose typed PIN fields and must redact them without logging or persistence.
- Mutating operations preserve dry-run and confirmation semantics.
- Destructive flows such as reset, credential deletion, and large-blob deletion require explicit confirmation.
- Factory reset must be executed shortly after authenticator power-up on many authenticators; consumers should collect any strong UI confirmation before reconnecting and then run a confirmed reset promptly.

## Engineering Journal

Passing `ctapkit.WithLogJournal` when opening an authenticator records CTAP
exchanges without changing any operation method. Each `ctap.command` entry
contains command metadata and bounded request/response CBOR diagnostic notation
in `cborDiagnostic`; fields marked for redaction by `go-ctap` are replaced
before the event reaches the journal. Internally, kit installs go-ctap's typed
`diagnostic.Sink`; application code does not need to receive or forward these
events.

The diagnostic payload is a normalized view of fields known to the installed
`go-ctap` protocol structures. Unknown CBOR fields are omitted, so it must not
be treated as a byte-exact wire capture. `originalBytes` reports the size of the
CBOR body; the command byte is reported separately as `commandCode`.

Non-CTAP runtime entries are metadata-only: they retain event kind, outcome,
correlation IDs, small non-secret parameters, and normalized failures, but do
not copy application request or response DTOs into the journal. This keeps
secret handling out of the logging layer and avoids duplicating application
state.

## Verification

Run the default checks with:

```powershell
go test ./... -count=1
go vet ./...
```

For authenticator lifecycle, interaction, or synchronization changes, also run:

```powershell
go test -race ./... -count=1
```
