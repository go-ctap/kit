package workflow

import (
	"context"
	"encoding/hex"

	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func (r Runner) ReadLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.ReadOperation,
) (applargeblobs.ReadReport, error) {
	if err := r.requireLargeBlobReadSupport(ctx, device); err != nil {
		return applargeblobs.ReadReport{}, err
	}

	inventory, err := r.loadLargeBlobCredentialInventory(
		ctx,
		device,
		largeBlobState,
		protocol.PermissionNone,
	)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	return r.readLargeBlobFromInventory(ctx, device, req, inventory)
}

func (r Runner) readLargeBlobFromInventory(
	ctx context.Context,
	device largeBlobArrayReader,
	req applargeblobs.ReadOperation,
	inventory *largeBlobInventory,
) (applargeblobs.ReadReport, error) {
	if err := ctx.Err(); err != nil {
		return applargeblobs.ReadReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseValidation))
	}

	if err := r.requireLargeBlobReadSupport(ctx, device); err != nil {
		return applargeblobs.ReadReport{}, err
	}

	target, err := rtcredentials.FindByHexID(inventory.credentials, req.CredentialIDHex)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}
	largeBlobKey := inventory.keys.get(target.RP.IDHashHex, target.Record.CredentialIDHex)
	if len(largeBlobKey) != 0 && len(largeBlobKey) != 32 {
		return applargeblobs.ReadReport{}, failure.New(failure.CodeLargeBlobKeyInvalid,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	state := applargeblobs.ReadStateMissing
	var raw []byte
	if len(largeBlobKey) == 32 {
		inventory, err = r.loadLargeBlobArrayIntoInventory(ctx, device, inventory)
		if err != nil {
			return applargeblobs.ReadReport{}, err
		}

		for _, candidate := range inventory.blobs {
			if !largeBlobMapConforming(candidate) {
				continue
			}

			compressed, err := crypto.OpenLargeBlob(largeBlobKey, candidate)
			if err != nil {
				continue
			}

			decrypted, err := crypto.DecompressLargeBlobData(compressed, candidate.OrigSize)
			secret.Zero(compressed)
			if err != nil {
				return applargeblobs.ReadReport{}, failure.Wrap(
					failure.CodeLargeBlobIntegrityFailure,
					err,
					failure.WithPhase(failure.PhaseDecode),
				)
			}

			state = applargeblobs.ReadStatePresent
			raw = decrypted

			break
		}
	}

	return applargeblobs.ReadReport{
		Device: r.env.Selected,
		Target: applargeblobs.BlobTarget{
			CredentialIDHex: target.Record.CredentialIDHex,
			RP:              target.RP,
			User:            target.User,
		},
		State:        state,
		RawHex:       hex.EncodeToString(raw),
		RawByteCount: len(raw),
		RawBytes:     raw,
	}, nil
}

func (r Runner) requireLargeBlobReadSupport(
	ctx context.Context,
	device authenticator.InfoProvider,
) error {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return err
	}
	support := buildLargeBlobSupportReport(info)
	if support.LargeBlobs && support.LargeBlobKeyExtension {
		return nil
	}

	return failure.New(failure.CodeLargeBlobUnsupported,
		failure.WithPhase(failure.PhaseDiscovery),
	)
}
