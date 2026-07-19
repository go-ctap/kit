package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/transport"
)

func TestCredentialInventoryDoesNotMarshalLargeBlobKey(t *testing.T) {
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &largeBlobWriteEventAuthenticator{}, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if bytes.Contains(raw, []byte(`"largeBlobKey":`)) ||
		bytes.Contains(raw, []byte("largeBlobKeyHex")) ||
		bytes.Contains(raw, []byte("01010101010101010101010101010101")) {
		t.Fatalf("credential inventory leaked largeBlobKey: %s", raw)
	}

	if !bytes.Contains(raw, []byte(`"largeBlobKeyState":"available"`)) {
		t.Fatalf("credential inventory omitted largeBlobKey availability: %s", raw)
	}
}

func TestLargeBlobWriteEventsFollowInteractionAndInventoryOrder(t *testing.T) {
	events := &recordingEventSink{}
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result == nil {
		t.Fatal("result = nil, want output")
	}

	want := []model.OperationStage{
		model.OperationStageInteractionRequired,
		model.OperationStageEnumeratingRPs,
		model.OperationStageEnumeratingCredentials,
	}

	got := eventStages(events.Events())
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}
}

func TestLargeBlobWriteUsesSeparateGrantForReadOnlyInventory(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{credentialManagementReadOnly: true}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if got := a.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}
	wantPermissions := []protocol.Permission{
		protocol.PermissionPersistentCredentialManagementReadOnly,
		protocol.PermissionLargeBlobWrite,
	}

	if !slices.Equal(a.tokenPermissions, wantPermissions) {
		t.Fatalf("token permissions = %#v, want %#v", a.tokenPermissions, wantPermissions)
	}
}

func TestLargeBlobWriteCapacityErrorKeepsPreview(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{maxSerializedLargeBlobArray: 16}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	requireFailureCode(t, err, failure.CodeLargeBlobArrayTooLarge)

	if output.Preview.SerializedLargeBlobArrayLimit != 16 {
		t.Fatalf("preview limit = %#v, want 16", output.Preview.SerializedLargeBlobArrayLimit)
	}

	if output.Preview.SerializedLargeBlobArraySizeAfter <= int(output.Preview.SerializedLargeBlobArrayLimit) {
		t.Fatalf("preview size after = %d, want over limit %d",
			output.Preview.SerializedLargeBlobArraySizeAfter,
			output.Preview.SerializedLargeBlobArrayLimit,
		)
	}
}

func TestLargeBlobWriteZeroCapacityMeansUnknownLimit(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob dry run: %v", err)
	}

	if output.Preview.SerializedLargeBlobArrayLimit != 0 {
		t.Fatalf("preview limit = %#v, want unknown", output.Preview.SerializedLargeBlobArrayLimit)
	}
}

func TestLargeBlobReadAndPreviewReadFreshAuthenticatorState(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.ReadLargeBlob(context.Background(), applargeblobs.ReadOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("read large blob: %v", err)
	}

	if _, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("preview write large blob: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 2 {
		t.Fatalf("RP enumerations = %d, want 2", got)
	}

	if got := a.credentialEnumerations.Load(); got != 2 {
		t.Fatalf("credential enumerations = %d, want 2", got)
	}

	if got := a.largeBlobReads.Load(); got != 2 {
		t.Fatalf("large blob reads = %d, want 2", got)
	}
}

func TestLargeBlobListReadsFreshReport(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("list large blobs: %v", err)
	}

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("list large blobs again: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 2 {
		t.Fatalf("RP enumerations = %d, want 2", got)
	}

	if got := a.credentialEnumerations.Load(); got != 2 {
		t.Fatalf("credential enumerations = %d, want 2", got)
	}

	if got := a.largeBlobReads.Load(); got != 2 {
		t.Fatalf("large blob reads = %d, want 2", got)
	}
}

func TestLargeBlobListAlwaysObservesCurrentAuthenticatorState(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("first ListLargeBlobs: %v", err)
	}

	added, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), []byte("refreshed"))
	if err != nil {
		t.Fatalf("encrypt refreshed blob: %v", err)
	}
	a.largeBlobs = []protocol.LargeBlob{added}

	output, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("refreshed ListLargeBlobs: %v", err)
	}

	if len(output.Credentials) != 1 || !output.Credentials[0].BlobPresent {
		t.Fatalf("refreshed large blob output = %#v, want one present credential blob", output)
	}

	cachedOutput, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("cached ListLargeBlobs after refresh: %v", err)
	}

	if len(cachedOutput.Credentials) != 1 || !cachedOutput.Credentials[0].BlobPresent {
		t.Fatalf("cached large blob output = %#v, want refreshed report", cachedOutput)
	}

	if got := a.rpEnumerations.Load(); got != 3 {
		t.Fatalf("RP enumerations = %d, want 3", got)
	}

	if got := a.credentialEnumerations.Load(); got != 3 {
		t.Fatalf("credential enumerations = %d, want 3", got)
	}

	if got := a.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}

	if got := a.largeBlobReads.Load(); got != 3 {
		t.Fatalf("large blob reads = %d, want 3", got)
	}
}

func TestLargeBlobDeleteLastBlobWritesEmptyArray(t *testing.T) {
	current, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), []byte("current"))
	if err != nil {
		t.Fatalf("encrypt current blob: %v", err)
	}

	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{current},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.DeleteLargeBlob(context.Background(), applargeblobs.DeleteOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("delete large blob: %v", err)
	}

	if output.Result == nil {
		t.Fatal("delete result = nil")
	}

	if output.Result.Operation != applargeblobs.MutationDelete {
		t.Fatalf("operation = %s, want delete", output.Result.Operation)
	}

	if output.Result.BlobCountAfter != 0 {
		t.Fatalf("blob count after = %d, want 0", output.Result.BlobCountAfter)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}

	if a.lastSetLargeBlobs == nil {
		t.Fatal("replacement blobs = nil, want empty slice")
	}

	if got := len(a.lastSetLargeBlobs); got != 0 {
		t.Fatalf("replacement blob count = %d, want 0", got)
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("CBOR enc mode: %v", err)
	}

	raw, err := encMode.Marshal(a.lastSetLargeBlobs)
	if err != nil {
		t.Fatalf("marshal replacement blobs: %v", err)
	}

	if !bytes.Equal(raw, []byte{0x80}) {
		t.Fatalf("replacement CBOR = %x, want 80 empty array", raw)
	}
}

func TestLargeBlobGarbageCollectNoopDoesNotWrite(t *testing.T) {
	matched, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), []byte("current"))
	if err != nil {
		t.Fatalf("encrypt matched blob: %v", err)
	}

	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{matched},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.GarbageCollectLargeBlobs(
		context.Background(),
		applargeblobs.GarbageCollectOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("garbage collect large blobs: %v", err)
	}

	if output.Result == nil {
		t.Fatal("garbage collect result = nil")
	}

	if !output.Result.Noop {
		t.Fatal("garbage collect result noop = false, want true")
	}

	if got := a.largeBlobWrites.Load(); got != 0 {
		t.Fatalf("large blob writes = %d, want 0", got)
	}

	if got := a.rpEnumerations.Load(); got != 1 {
		t.Fatalf("RP enumerations = %d, want 1", got)
	}

	if got := a.credentialEnumerations.Load(); got != 1 {
		t.Fatalf("credential enumerations = %d, want 1", got)
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}
}

func TestLargeBlobGarbageCollectSkipsNonConformingEntries(t *testing.T) {
	nonConforming := protocol.LargeBlob{
		Ciphertext: []byte("not-a-gcm-ciphertext"),
		Nonce:      []byte("short"),
		OrigSize:   4,
	}
	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{nonConforming},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.GarbageCollectLargeBlobs(
		context.Background(),
		applargeblobs.GarbageCollectOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("garbage collect large blobs: %v", err)
	}

	if output.Result == nil {
		t.Fatal("garbage collect result = nil")
	}

	if !output.Result.Noop {
		t.Fatal("garbage collect result noop = false, want true")
	}

	if output.Result.BlobCountAfter != 1 {
		t.Fatalf("blob count after = %d, want 1", output.Result.BlobCountAfter)
	}

	if output.Result.UnmatchedBlobCount != 0 {
		t.Fatalf("unmatched blob count = %d, want 0", output.Result.UnmatchedBlobCount)
	}

	if got := a.largeBlobWrites.Load(); got != 0 {
		t.Fatalf("large blob writes = %d, want 0", got)
	}
}

func TestLargeBlobGarbageCollectRemovesOnlyUnmatchedEntries(t *testing.T) {
	matched, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), []byte("current"))
	if err != nil {
		t.Fatalf("encrypt matched blob: %v", err)
	}
	unmatched, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x02}, 32), []byte("orphan"))
	if err != nil {
		t.Fatalf("encrypt unmatched blob: %v", err)
	}

	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{matched, unmatched},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.GarbageCollectLargeBlobs(
		context.Background(),
		applargeblobs.GarbageCollectOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("garbage collect large blobs: %v", err)
	}

	if output.Result == nil {
		t.Fatal("garbage collect result = nil")
	}

	if output.Result.DeletedBlobCount != 1 {
		t.Fatalf("deleted blob count = %d, want 1", output.Result.DeletedBlobCount)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}

	if got := len(a.lastSetLargeBlobs); got != 1 {
		t.Fatalf("replacement blob count = %d, want 1", got)
	}

	if _, err := crypto.DecryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), a.lastSetLargeBlobs[0]); err != nil {
		t.Fatalf("replacement blob is not decryptable by known largeBlobKey: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 1 {
		t.Fatalf("RP enumerations = %d, want 1", got)
	}

	if got := a.credentialEnumerations.Load(); got != 1 {
		t.Fatalf("credential enumerations = %d, want 1", got)
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}
}

func TestLargeBlobGarbageCollectAllUnmatchedWritesEmptyArray(t *testing.T) {
	unmatched, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x02}, 32), []byte("orphan"))
	if err != nil {
		t.Fatalf("encrypt unmatched blob: %v", err)
	}

	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{unmatched},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.GarbageCollectLargeBlobs(
		context.Background(),
		applargeblobs.GarbageCollectOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("garbage collect large blobs: %v", err)
	}

	if output.Result == nil {
		t.Fatal("garbage collect result = nil")
	}

	if output.Result.Noop {
		t.Fatal("garbage collect result noop = true, want false")
	}

	if output.Result.DeletedBlobCount != 1 {
		t.Fatalf("deleted blob count = %d, want 1", output.Result.DeletedBlobCount)
	}

	if output.Result.BlobCountAfter != 0 {
		t.Fatalf("blob count after = %d, want 0", output.Result.BlobCountAfter)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}

	if a.lastSetLargeBlobs == nil {
		t.Fatal("replacement blobs = nil, want empty slice")
	}

	if got := len(a.lastSetLargeBlobs); got != 0 {
		t.Fatalf("replacement blob count = %d, want 0", got)
	}
}

func TestLargeBlobWritePINOnlyFlowDoesNotRequestUserVerification(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{
			PIN: []byte("1234"),
		}, nil
	})

	result, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result == nil {
		t.Fatal("result = nil, want output")
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if got := a.uvCalls.Load(); got != 0 {
		t.Fatalf("UV token calls = %d, want 0", got)
	}

	want := []model.OperationStage{
		model.OperationStageInteractionRequired,
		model.OperationStageEnumeratingRPs,
		model.OperationStageEnumeratingCredentials,
	}

	got := eventStages(events.Events())
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindUserVerification {
			t.Fatal("user-verification interaction emitted for PIN-only authenticator")
		}
	}
}

func TestLargeBlobWritePreparedRefreshRequestsPINOnce(t *testing.T) {
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	var requests []model.InteractionRequest
	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		requests = append(requests, req)

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if _, err := session.ListLargeBlobs(
		context.Background(),
		session.operationOptions(WithInteractionHandler(handler))...,
	); err != nil {
		t.Fatalf("ListLargeBlobs refresh: %v", err)
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if len(requests) != 1 {
		t.Fatalf("PIN requests = %d, want 1", len(requests))
	}

	if got, want := requests[0].Permission, "credentialManagement,largeBlobWrite"; got != want {
		t.Fatalf("PIN permission = %q, want %q", got, want)
	}
}

func TestLargeBlobWritePINVerificationFlowSkipsUVForUVCapableAuthenticator(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinPreferredLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindPIN {
			t.Fatalf("interaction kind = %s, want PIN", req.Kind)
		}

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})

	result, err := session.WriteLargeBlob(
		context.Background(),
		applargeblobs.WriteOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
		},
		session.operationOptions(WithVerificationFlow(VerificationFlowPIN), WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if result.Result == nil {
		t.Fatal("mutation result = nil, want output")
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if got := a.uvCalls.Load(); got != 0 {
		t.Fatalf("UV token calls = %d, want 0", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindUserVerification {
			t.Fatal("user-verification interaction emitted for PIN verification flow")
		}
	}
}
