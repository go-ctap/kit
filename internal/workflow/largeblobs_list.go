package workflow

import (
	"context"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
)

func (r Runner) ListLargeBlobs(ctx context.Context, device LargeBlobDevice) (applargeblobs.ListReport, error) {
	inventory, err := r.credentialInventoryReport(ctx, device, protocol.PermissionNone)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}
	defer zeroCredentialInventoryReport(&inventory)

	rep, err := r.listLargeBlobsFromInventory(ctx, device, inventory)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}

	if err := ctx.Err(); err != nil {
		return applargeblobs.ListReport{}, errornorm.Annotate(
			err,
			errornorm.WithPhase(failure.PhaseDiscovery),
		)
	}

	return rep, nil
}

type listBuildContext struct {
	selected           report.DeviceReport
	support            applargeblobs.SupportReport
	blobs              []protocol.LargeBlob
	matchedBlobIndexes map[int]bool
}

func (r Runner) listLargeBlobsFromInventory(
	ctx context.Context,
	device LargeBlobDevice,
	inventory appcredentials.InventoryReport,
) (applargeblobs.ListReport, error) {
	if err := ctx.Err(); err != nil {
		return applargeblobs.ListReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	support := buildLargeBlobSupportReport(device.GetInfo())
	report := applargeblobs.ListReport{
		Device:  r.env.Selected,
		Support: support,
	}

	var (
		blobs []protocol.LargeBlob
		err   error
	)

	if support.LargeBlobs {
		blobs, err = r.readLargeBlobArray(ctx, device)
		if err != nil {
			return applargeblobs.ListReport{}, err
		}

		report.Array.Read = true
		report.Array.BlobCount = len(blobs)
	}

	matchedBlobIndexes := make(map[int]bool)
	buildCtx := listBuildContext{
		selected:           r.env.Selected,
		support:            support,
		blobs:              blobs,
		matchedBlobIndexes: matchedBlobIndexes,
	}

	report.Credentials = make([]applargeblobs.ListCredential, 0, int(inventory.Summary.TotalCredentials))
	for _, group := range inventory.Groups {
		for _, record := range group.Credentials {
			row, err := buildListCredentialRow(buildCtx, group, record)
			if err != nil {
				return applargeblobs.ListReport{}, err
			}

			report.Credentials = append(report.Credentials, row)
		}
	}

	report.Array.MatchedBlobCount = len(matchedBlobIndexes)

	report.Array.UnmatchedBlobCount = report.Array.BlobCount - report.Array.MatchedBlobCount
	if report.Array.UnmatchedBlobCount < 0 {
		report.Array.UnmatchedBlobCount = 0
	}

	return report, nil
}

func buildListCredentialRow(
	ctx listBuildContext,
	group appcredentials.CredentialGroup,
	record appcredentials.CredentialRecord,
) (applargeblobs.ListCredential, error) {
	row := applargeblobs.ListCredential{
		DeviceFingerprint: ctx.selected.Fingerprint,
		CredentialIDHex:   record.CredentialIDHex,
		RP: appcredentials.RelyingParty{
			ID:        group.RPID,
			Name:      group.RPName,
			IDHashHex: group.RPIDHashHex,
		},
		User: appcredentials.UserIdentity{
			UserIDHex:   record.UserIDHex,
			Name:        record.UserName,
			DisplayName: record.DisplayName,
		},
		LargeBlobKeyState: applargeblobs.LargeBlobKeyMissing,
		BlobState:         applargeblobs.BlobStateUnsupported,
	}

	if len(record.LargeBlobKey) == 0 {
		if ctx.support.LargeBlobs {
			row.BlobState = applargeblobs.BlobStateUnknownKeyMissing
		}

		return row, nil
	}

	row.LargeBlobKeyState = applargeblobs.LargeBlobKeyAvailable

	if !ctx.support.LargeBlobs {
		return row, nil
	}

	row.BlobState = applargeblobs.BlobStateMissing

	key := record.LargeBlobKey
	defer secret.Zero(key)

	for index, candidate := range ctx.blobs {
		if ctx.matchedBlobIndexes[index] {
			continue
		}

		raw, err := crypto.DecryptLargeBlob(key, candidate)
		if err != nil {
			continue
		}
		defer secret.Zero(raw)

		ctx.matchedBlobIndexes[index] = true
		row.BlobPresent = true
		row.BlobState = applargeblobs.BlobStatePresent
		row.BlobByteCount = len(raw)

		break
	}

	return row, nil
}
