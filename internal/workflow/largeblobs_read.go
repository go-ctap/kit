package workflow

import (
	"context"
	"encoding/hex"
	"slices"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func (r Runner) readLargeBlob(ctx context.Context, req model.ReadLargeBlobOperation) (applargeblobs.ReadReport, error) {
	report, err := r.credentialInventoryReport(ctx, protocol.PermissionNone)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}
	defer zeroCredentialInventoryReport(&report)

	return r.readLargeBlobFromInventory(ctx, applargeblobs.ReadRequest{
		CredentialIDHex: req.CredentialIDHex,
		DecodeMode:      req.DecodeMode,
	}, report)
}

func (r Runner) readLargeBlobFromInventory(
	ctx context.Context,
	req applargeblobs.ReadRequest,
	inventory appcredentials.InventoryReport,
) (applargeblobs.ReadReport, error) {
	if err := ctx.Err(); err != nil {
		return applargeblobs.ReadReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseValidation))
	}

	target, err := appcredentials.FindCredentialByHexID(inventory, req.CredentialIDHex)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	support := buildLargeBlobSupportReport(r.env.Authenticator.GetInfo())
	result := applargeblobs.ReadReport{
		Device:  r.env.Selected,
		Support: support,
		Target: applargeblobs.BlobTarget{
			CredentialIDHex: target.Record.CredentialIDHex,
			RP:              target.RP,
			User:            target.User,
		},
		Array: applargeblobs.ArrayState{BlobState: applargeblobs.BlobStateUnsupported},
	}

	if len(target.Record.LargeBlobKey) == 0 {
		result.LargeBlobKeyState = applargeblobs.LargeBlobKeyMissing
		result.Array = applargeblobs.ArrayState{BlobState: applargeblobs.BlobStateUnknownKeyMissing}
		result.Decode = applargeblobs.DecodeLargeBlob(nil, false, req.DecodeMode)

		return result, nil
	}

	result.LargeBlobKeyState = applargeblobs.LargeBlobKeyAvailable

	if !support.LargeBlobs {
		result.Decode = applargeblobs.DecodeLargeBlob(nil, false, req.DecodeMode)

		return result, nil
	}

	key := slices.Clone(target.Record.LargeBlobKey)
	defer secret.Zero(key)

	blobs, err := r.readLargeBlobArray(ctx)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	result.Array = applargeblobs.ArrayState{
		Read:      true,
		BlobCount: len(blobs),
		BlobState: applargeblobs.BlobStateMissing,
	}

	for _, candidate := range blobs {
		raw, err := crypto.DecryptLargeBlob(key, candidate)
		if err != nil {
			continue
		}
		// it's fine to call defer in this for like that
		defer secret.Zero(raw)

		result.RawBytes = slices.Clone(raw)
		result.RawHex = hex.EncodeToString(raw)
		result.RawByteCount = len(raw)
		result.BlobPresent = true
		result.Array.BlobPresent = true
		result.Array.BlobState = applargeblobs.BlobStatePresent
		result.Array.BlobSize = len(raw)
		result.Decode = applargeblobs.DecodeLargeBlob(raw, true, req.DecodeMode)

		return result, nil
	}

	result.Decode = applargeblobs.DecodeLargeBlob(nil, false, req.DecodeMode)

	return result, nil
}
