package workflow

import (
	"context"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func (r Runner) ListLargeBlobs(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
) (applargeblobs.ListReport, error) {
	inventory, err := r.refreshLargeBlobInventory(ctx, device, largeBlobState, protocol.PermissionNone)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}

	report, err := r.listLargeBlobsFromInventory(ctx, device, inventory)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}

	return report, nil
}

type listCredentialKey struct {
	target applargeblobs.BlobTarget
	key    []byte
}

func (r Runner) listLargeBlobsFromInventory(
	ctx context.Context,
	device authenticator.InfoProvider,
	inventory *largeBlobInventory,
) (applargeblobs.ListReport, error) {
	if err := ctx.Err(); err != nil {
		return applargeblobs.ListReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}
	support := buildLargeBlobSupportReport(info)
	summary := applargeblobs.ListArraySummary{}
	var entries []applargeblobs.ArrayEntry
	if support.LargeBlobs {
		keys := listCredentialKeys(inventory)
		entries = make([]applargeblobs.ArrayEntry, 0, len(inventory.blobs))
		summary.Read = true
		summary.BlobCount = len(inventory.blobs)

		for index, blob := range inventory.blobs {
			entry := classifyLargeBlobEntry(index, blob, keys)
			entries = append(entries, entry)

			switch entry.State {
			case applargeblobs.EntryStateMatched:
				summary.MatchedBlobCount++
			case applargeblobs.EntryStateOrphaned:
				summary.OrphanedBlobCount++
			case applargeblobs.EntryStateNonconforming:
				summary.NonconformingBlobCount++
			case applargeblobs.EntryStateCorrupt:
				summary.CorruptBlobCount++
			}
		}
	}

	return applargeblobs.ListReport{
		Device:  r.env.Selected,
		Support: support,
		Array:   summary,
		Entries: entries,
	}, nil
}

func listCredentialKeys(inventory *largeBlobInventory) []listCredentialKey {
	keys := make([]listCredentialKey, 0, inventory.credentials.Summary.TotalCredentials)
	for _, group := range inventory.credentials.Groups {
		for _, record := range group.Credentials {
			key := inventory.keys.get(group.RPIDHashHex, record.CredentialIDHex)
			if len(key) != 32 {
				continue
			}

			keys = append(keys, listCredentialKey{
				target: applargeblobs.BlobTarget{
					CredentialIDHex: record.CredentialIDHex,
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
				},
				key: key,
			})
		}
	}

	return keys
}

func classifyLargeBlobEntry(
	index int,
	blob protocol.LargeBlob,
	keys []listCredentialKey,
) applargeblobs.ArrayEntry {
	entry := applargeblobs.ArrayEntry{
		Index:                    index,
		State:                    applargeblobs.EntryStateNonconforming,
		CiphertextByteCount:      len(blob.Ciphertext),
		DeclaredPayloadByteCount: blob.OrigSize,
	}
	if !largeBlobMapConforming(blob) {
		return entry
	}

	for _, candidate := range keys {
		compressed, err := crypto.OpenLargeBlob(candidate.key, blob)
		if err != nil {
			continue
		}

		target := candidate.target
		entry.Target = &target
		raw, err := crypto.DecompressLargeBlobData(compressed, blob.OrigSize)
		secret.Zero(compressed)
		if err != nil {
			entry.State = applargeblobs.EntryStateCorrupt

			return entry
		}

		entry.State = applargeblobs.EntryStateMatched
		entry.PayloadByteCount = len(raw)
		secret.Zero(raw)

		return entry
	}

	entry.State = applargeblobs.EntryStateOrphaned

	return entry
}
