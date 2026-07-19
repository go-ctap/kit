package workflow

import (
	"context"
	"encoding/hex"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	rtcredentials "github.com/go-ctap/kit/internal/credentials"
	"github.com/go-ctap/kit/internal/errornorm"
	rtlargeblobs "github.com/go-ctap/kit/internal/largeblobs"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func (r Runner) ReadLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.ReadOperation,
) (applargeblobs.ReadReport, error) {
	inventory, err := r.loadLargeBlobInventory(ctx, device, largeBlobState, protocol.PermissionNone)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	return r.readLargeBlobFromInventory(ctx, device, req, inventory)
}

func (r Runner) readLargeBlobFromInventory(
	ctx context.Context,
	device LargeBlobDevice,
	req applargeblobs.ReadOperation,
	inventory *largeBlobInventory,
) (applargeblobs.ReadReport, error) {
	if err := ctx.Err(); err != nil {
		return applargeblobs.ReadReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseValidation))
	}

	target, err := rtcredentials.FindByHexID(inventory.credentials, req.CredentialIDHex)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	support := buildLargeBlobSupportReport(device.GetInfo())
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
		result.Decode = rtlargeblobs.Decode(nil, false, req.DecodeMode)

		return result, nil
	}

	result.LargeBlobKeyState = applargeblobs.LargeBlobKeyAvailable

	if !support.LargeBlobs {
		result.Decode = rtlargeblobs.Decode(nil, false, req.DecodeMode)

		return result, nil
	}

	key := target.Record.LargeBlobKey

	result.Array = applargeblobs.ArrayState{
		Read:      true,
		BlobCount: len(inventory.blobs),
		BlobState: applargeblobs.BlobStateMissing,
	}

	for _, candidate := range inventory.blobs {
		raw, err := crypto.DecryptLargeBlob(key, candidate)
		if err != nil {
			continue
		}

		result.RawBytes = raw
		result.RawHex = hex.EncodeToString(raw)
		result.RawByteCount = len(raw)
		result.BlobPresent = true
		result.Array.BlobPresent = true
		result.Array.BlobState = applargeblobs.BlobStatePresent
		result.Array.BlobSize = len(raw)
		result.Decode = rtlargeblobs.Decode(raw, true, req.DecodeMode)

		return result, nil
	}

	result.Decode = rtlargeblobs.Decode(nil, false, req.DecodeMode)

	return result, nil
}
