# Machine-Readable Error Contract

Public runtime failures use `model/failure`. Go callers receive a
`*failure.Error`; service DTOs expose the same data as `*failure.Failure` under
their `error` or `failure` field.

## Go API

```go
result, err := session.Run(ctx, operation, handler)
if err != nil {
	if failure.IsCode(err, failure.CodeCredentialNotFound) {
		// Choose recovery or localized UI by the stable code.
	}

	snapshot := failure.Snapshot(err)
	_ = snapshot
}
```

- `failure.New` creates a semantic error without a lower-level cause.
- `failure.Wrap` retains a cause for trusted in-process `errors.Is` and
  `errors.As` use.
- `failure.IsCode` matches a stable semantic code.
- `failure.CodeOf` returns `("", false)` for nil and `INTERNAL_ERROR` for an
  unknown non-nil Go error.
- `failure.Snapshot` returns a detached, transport-safe DTO, or nil for a nil
  error.
- `failure.Error.Error()` returns only the code string, never diagnostic prose.

Use `failure.IsCode`, not `errors.Is`, for semantic conditions. `errors.Is` and
`errors.As` are only for inspecting a retained low-level cause inside the Go
process.

## Wire Shape

```json
{
  "code": "PIN_INVALID",
  "category": "invalid-state",
  "operation": "webauthn.getAssertion",
  "phase": "token-acquisition",
  "ctap": {
    "command": "authenticatorClientPIN",
    "commandCode": 6,
    "subCommandFamily": "clientPIN",
    "subCommand": "getPinUvAuthTokenUsingPinWithPermissions",
    "subCommandCode": 9,
    "status": "CTAP2_ERR_PIN_INVALID",
    "statusCode": 49
  }
}
```

Only `code` and `category` are always present.

| Field | Meaning |
| --- | --- |
| `code` | Stable localization and recovery key. |
| `category` | Coarse recovery class; not a localization key. |
| `params` | Allowlisted non-secret interpolation values. |
| `operation` | Public operation kind. |
| `phase` | Runtime phase that owned the failure. |
| `ctap` | Exact authenticator command and status provenance. |

`failure.Failure` is an ordinary typed struct. It does not implement custom
JSON marshaling, so Wails can generate a typed binding. Runtime code constructs
errors through `New` or `Wrap` and service DTOs use `Snapshot`; those boundaries
apply the registry and copy mutable maps and CTAP details.

## Stable Registry

`failure.Code` values are public compatibility surface. Do not rename or reuse
an existing value for a different condition. Changing a code's category or
removing an allowed parameter is also breaking.

Construction and snapshots apply these rules:

- an unknown code becomes `INTERNAL_ERROR`;
- category comes from the code registry;
- unknown or invalid parameters are removed;
- unknown operation names and phases are removed;
- CTAP symbolic names are derived from their numeric values.

Frontends must retain a generic localized fallback for codes introduced by a
newer runtime.

## Parameters And Secrets

The current interpolation allowlist is:

| Code | Parameters |
| --- | --- |
| `PIN_REQUIRED` | `field` |
| `MDS_FETCH_FAILED` | `httpStatus` |
| `CONFORMANCE_TARGET_INVALID` | `specification`, `profile` |
| `MIN_PIN_LENGTH_DECREASE_NOT_ALLOWED` | `requested`, `current` |
| `LARGE_BLOB_ARRAY_TOO_LARGE` | `requested`, `limit` |

`field`, `specification`, and `profile` accept registered enum values.
`requested`, `current`, and `limit` accept canonical unsigned decimal values.
`httpStatus` accepts decimal HTTP status codes from 100 through 599.

Parameters must never contain PINs, `pinUvAuthToken` values, reset phrases,
credential material, identifiers, URLs, paths, raw payloads, or `err.Error()`
text. The wrapped Go cause is not part of `Failure` and is therefore absent
from snapshots and JSON.

## CTAP Provenance

For authenticator errors, numeric command and status values are authoritative.
Symbolic names are included only when the pinned upstream protocol package
recognizes the value. Unknown reserved, extension, and vendor values keep their
numeric code and omit the name.

Command-aware mapping can assign different semantic codes to the same raw
status. For example, `CTAP2_ERR_NOT_ALLOWED` becomes:

- `ASSERTION_NOT_ALLOWED` for GetAssertion;
- `ASSERTION_CONTINUATION_UNAVAILABLE` for GetNextAssertion;
- `RESET_WINDOW_EXPIRED` for Reset.

ClientPIN token acquisition records the ClientPIN command and subcommand while
retaining the outer public operation. LargeBlobs `get` and `set` request fields
are CBOR map keys, not CTAP subcommands, and are never emitted as subcommand
metadata.

The original typed CTAP or transport cause remains available only through the
in-process Go error chain. Consumers must not forward or concatenate its text.
