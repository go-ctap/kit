# go-ctap/kit

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/kit.svg)](https://pkg.go.dev/github.com/go-ctap/kit)
[![Go](https://github.com/go-ctap/kit/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/kit/actions/workflows/go.yml)

`go-ctap/kit` is a reusable Go runtime for applications that work with local
FIDO2 authenticators. It provides device discovery, safe multi-step workflows,
typed results, user interaction callbacks, and stable errors.

The library is the shared runtime used by the `go-ctap` application family. It
can be used by desktop, command-line, and terminal applications, but it does not
contain any user interface code.

> [!WARNING]
> The project is in active development and is not yet v1.0. Minor releases may
> include breaking API changes.

## Support

The runtime is built on [`go-ctap/ctap`](https://github.com/go-ctap/ctap) and
supports authenticator features from CTAP 2.0 through CTAP 2.3. Each operation
still depends on the capabilities reported by the connected authenticator.

Main features include:

- authenticator inspection and CTAP conformance reports;
- PIN setup and change;
- built-in user verification and biometric enrollment;
- authenticator configuration and factory reset;
- resident credential listing, update, and deletion;
- large-blob reading, writing, deletion, and garbage collection;
- WebAuthn credential creation and assertion;
- optional vendor device model, firmware, and interface metadata;
- FIDO Metadata Service (MDS3) lookup and verification;
- operation progress events and interaction callbacks;
- bounded and redacted CTAP diagnostic logs.

This repository is a library, not a CLI. It does not provide command parsing,
prompts, confirmation screens, tables, JSON rendering, or product-specific
workflows. Applications must provide those parts.

## Transports

| Mode | Platform | Behavior |
|---|---|---|
| `transport.ModeAuto` | Linux, macOS, Windows | Uses HID on Linux and macOS. On Windows, it uses HID for an elevated process and the Windows proxy otherwise. |
| `transport.ModeHID` | Linux, macOS, Windows | Opens the authenticator through direct USB HID access. |
| `transport.ModeWindowsProxy` | Windows | Connects to a running [`go-ctap/windows-proxy`](https://github.com/go-ctap/windows-proxy). |

NFC, BLE, hybrid, and generic smart-card transports are not part of this
runtime.

## Installation

```sh
go get github.com/go-ctap/kit@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

The example below discovers authenticators, opens the first one, and reads its
public information. A real application should let the user choose when more
than one device is available.

```go
package main

import (
	"context"
	"fmt"
	"log"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/transport"
)

func main() {
	ctx := context.Background()

	devices, err := ctapkit.DiscoverDevices(ctx, transport.ModeAuto)
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no FIDO2 authenticator found")
	}

	authenticator, err := ctapkit.OpenAuthenticator(ctx, devices[0])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := authenticator.Close(); err != nil {
			log.Printf("close authenticator: %v", err)
		}
	}()

	inspection, err := authenticator.Inspect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("product: %s\n", inspection.Device.Product)
	fmt.Printf("versions: %v\n", inspection.Info.Versions)
	fmt.Printf("AAGUID: %s\n", inspection.Info.AAGUID)
}
```

`DiscoverDevices` returns `ctapkit.Device` handles. Use `Device.Report`
to show safe discovery details. `ctapkit.SelectDevice` can resolve a displayed
fingerprint or ordinal alias from the same discovery result.

## Runtime lifecycle

A normal application follows this lifecycle:

1. Discover the connected devices.
2. Choose one `ctapkit.Device` from that discovery result.
3. Open it with `ctapkit.OpenAuthenticator`.
4. Run typed operations on the returned `*ctapkit.Authenticator`.
5. Close it when the selected device changes or the application exits.

An `Authenticator` owns one open transport channel, its token cache, and its
close and cancellation state. It runs one complete workflow at a time. This
prevents two multi-command operations on the same channel from mixing with each
other.

Credential-list and configuration workflows read current state per operation.
Large-blob workflows are the deliberate exception: `ListLargeBlobs` refreshes
private in-memory inventory for the selected open authenticator, and read,
preview, and mutation operations reuse that inventory. A successful mutation
updates the retained large-blob array. Credential mutations, WebAuthn
large-blob writes, and factory reset invalidate the inventory so the next
large-blob operation reloads it. Dry runs leave it unchanged, and an explicit
`ListLargeBlobs` always refreshes it. The state never crosses the authenticator
boundary, and its credential keys are cleared on invalidation, refresh, and
close.

`Authenticator.Close` is safe to call more than once or while another goroutine
is using the authenticator. It cancels the active operation, clears owned secret
state, and closes the transport.

## Operations

The root `ctapkit` package is the public runtime facade. Operation inputs and
results are typed DTOs from the `model` packages.

| Area          | Main methods                                                                                                       |
|---------------|--------------------------------------------------------------------------------------------------------------------|
| Inspection    | `Inspect`                                                                                                          |
| Configuration | `ConfigStatus`, `SetPIN`, `ChangePIN`, `SetAlwaysUV`, `SetMinPINLength`, `EnableLongTouchForReset`, `ResetFactory` |
| Biometrics    | `BioSensorInfo`, `BioList`, `BioEnroll`, `BioRename`, `BioRemove`                                                  |
| Credentials   | `ListCredentials`, `CredentialStoreState`, `DeleteCredential`, `UpdateCredentialUser`                              |
| Large blobs   | `ReadLargeBlob`, `ListLargeBlobs`, `WriteLargeBlob`, `DeleteLargeBlob`, `GarbageCollectLargeBlobs`                 |
| WebAuthn      | `MakeCredential`, `GetAssertion`                                                                                   |
| Device metadata | `CanProbeDeviceMetadata`, `ProbeDeviceMetadata`                                                                  |
| Metadata      | `ctapkit.LookupMDS`                                                                                                |

Operation methods return pointers to concrete result types. A nil pointer means
that the workflow did not start. A non-nil value may contain a preview or other
partial data together with an error.

## Interactions and verification

Some operations need a PIN, built-in user verification, or a physical touch.
Pass `ctapkit.WithInteractionHandler` to the operation that may need this input.
The handler receives a typed `model.InteractionRequest` and returns a typed
`model.InteractionResponse`.

Progress is separate from interaction. Pass `ctapkit.WithEventSink` to receive
typed `model.OperationEvent` values, such as credential enumeration or
biometric sample progress.

Both callbacks belong to one operation. The runtime does not store them on the
open authenticator. This makes request ownership and cancellation easier for
applications with several tasks or windows.

The default verification flow prefers built-in user verification when the
authenticator supports it and falls back to PIN when CTAP allows this. To ask
for PIN first, pass:

```go
ctapkit.WithVerificationFlow(ctapkit.VerificationFlowPIN)
```

The authenticator always makes the final decision about whether a verification
method succeeds.

## Previews and dry runs

Mutating operations return a typed preview before they change authenticator
state. Many operation DTOs also have a `DryRun` field.

```go
output, err := authenticator.DeleteCredential(
	ctx,
	credentials.DeleteOperation{
		CredentialIDHex: credentialID,
		DryRun:          true,
	},
)
```

For a dry run, the preview is filled and the mutation result is nil. The
consumer must show warnings, ask for confirmation when needed, and decide
whether to run the real operation. The runtime does not implement product
confirmation rules.

## Errors

Public failures use `model/failure`. Each known error has a stable code and a
recovery category. CTAP errors can also include the command, subcommand, and
status that caused the failure.

```go
result, err := authenticator.ListCredentials(ctx)
if err != nil {
	if failure.IsCode(err, failure.CodeInteractionHandlerRequired) {
		// Run the operation again with an interaction handler.
	}

	snapshot := failure.Snapshot(err)
	_ = result
	_ = snapshot
}
```

Use `failure.IsCode` for application decisions. Do not parse `err.Error()`.
The full wire format and recovery rules are described in
[`docs/error-contract.md`](docs/error-contract.md).

## FIDO Metadata Service

`ctapkit.LookupMDS` fetches and verifies the FIDO MDS3 blob, finds an entry by
AAGUID, and caches the verified blob in memory and on disk.

```go
inspection, err := authenticator.Inspect(ctx)
if err != nil {
	return err
}

metadata, err := ctapkit.LookupMDS(ctx, inspection.Info.AAGUID)
if err != nil {
	return err
}
```

The runtime verifies disk cache entries again before it uses them. Applications
own metadata presentation and trust policy.

## Diagnostic journal

Create a journal and pass it when the authenticator is opened:

```go
journal := ctapkit.NewLogJournal()

authenticator, err := ctapkit.OpenAuthenticator(
	ctx,
	device,
	ctapkit.WithLogJournal(journal),
)
if err != nil {
	return err
}

batch := journal.Read(0)
```

The journal stores a bounded, in-memory list of CTAP exchanges. Request and
response CBOR is decoded through known protocol types and sensitive fields are
redacted. It is useful for debugging, but it is not a byte-exact wire capture.
Unknown CBOR fields may be missing.

Diagnostic records can still contain device, relying-party, user, credential,
or biometric identifiers. Treat them as sensitive data.

## Packages

| Package                                                                             | Use it for                                                                                |
|-------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `ctapkit`                                                                           | Device discovery, authenticator lifecycle, typed operations, MDS, and diagnostic journals |
| `model`                                                                             | Shared event, interaction, and log DTOs                                                   |
| `model/config`                                                                      | Configuration and biometric operation DTOs                                                |
| `model/credentials`                                                                 | Credential inventory and mutation DTOs                                                    |
| `model/inspect`                                                                     | Authenticator inspection DTOs                                                             |
| `model/largeblobs`                                                                  | Large-blob operation DTOs                                                                 |
| `model/webauthn`                                                                    | WebAuthn operation DTOs                                                                   |
| `model/failure`                                                                     | Stable public error codes and snapshots                                                   |
| `model/conformance`, `model/mds`, `model/operation`, `model/report`, `model/safety` | Shared report and contract DTOs                                                           |
| `transport`                                                                         | HID and Windows proxy discovery modes                                                     |

Packages under `internal` contain runtime implementation details and are not a
public API.

## Safety and usage notes

- Always close `Authenticator` when it is no longer needed.
- Treat authenticator state as changeable between commands.
- Do not log or store PINs, PIN/UV tokens, credential secrets, or large-blob
  payloads.
- PIN fields in public configuration operation DTOs are omitted during JSON
  encoding.
- Runtime-owned PIN/UV token buffers are wiped when they are released.
- A dry run is a preview, not authorization to run a mutation.
- Credential deletion, large-blob deletion, and factory reset need clear
  confirmation in the consuming application.
- Many displayless authenticators require factory reset soon after power-up.
  Ask for confirmation before reconnecting or power-cycling the device.
- One opened authenticator runs its own workflows one at a time. It does not
  create a process-wide or device-wide lock.

More lifecycle details are available in
[`docs/current-runtime-flows.md`](docs/current-runtime-flows.md).

## Development

Run the default checks with:

```sh
go test ./... -count=1
go vet ./...
```

For authenticator lifecycle, interaction, token, or synchronization changes,
also run:

```sh
go test -race ./... -count=1
```

Hardware-dependent behavior must not be required by the default test suite.

## References

- [`go-ctap/ctap`](https://github.com/go-ctap/ctap)
- [`go-ctap/hid`](https://github.com/go-ctap/hid)
- [`go-ctap/windows-proxy`](https://github.com/go-ctap/windows-proxy)
- [Client to Authenticator Protocol 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
