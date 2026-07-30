package workflow

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	"github.com/samber/lo"
)

func (r Runner) ListCredentials(ctx context.Context, device authenticator.CredentialInventoryReader) (appcredentials.InventoryReport, error) {
	return r.credentialInventory(ctx, device, protocol.PermissionNone, nil)
}

type credentialInventorySnapshot struct {
	info     protocol.AuthenticatorGetInfoResponse
	metadata protocol.AuthenticatorCredentialManagementResponse
	groups   []credentialInventoryGroupSnapshot
}

type credentialInventoryGroupSnapshot struct {
	rp          protocol.AuthenticatorCredentialManagementResponse
	credentials []protocol.AuthenticatorCredentialManagementResponse
}

func (snapshot *credentialInventorySnapshot) zeroLargeBlobKeys() {
	if snapshot == nil {
		return
	}

	for groupIndex := range snapshot.groups {
		for credentialIndex := range snapshot.groups[groupIndex].credentials {
			credential := &snapshot.groups[groupIndex].credentials[credentialIndex]
			secret.Zero(credential.LargeBlobKey)
			credential.LargeBlobKey = nil
		}
	}
}

func (r Runner) credentialInventory(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	grantPermission protocol.Permission,
	keys largeBlobKeyStore,
) (appcredentials.InventoryReport, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}
	permission, err := inventoryPermission(info)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	if grantPermission == protocol.PermissionNone {
		grantPermission = permission
	}

	if !grantCoversInventoryPermission(grantPermission, permission) {
		return appcredentials.InventoryReport{}, failure.New(
			failure.CodeInternalError,
			failure.WithPhase(failure.PhaseTokenAcquisition),
		)
	}

	var snapshot credentialInventorySnapshot
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: grantPermission,
		ReplaySafe: true,
	}, func(token []byte) error {
		current, err := r.readCredentialInventorySnapshot(ctx, device, token)
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			current.zeroLargeBlobKeys()

			return errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
		}

		snapshot = current

		return nil
	})
	if err != nil {
		snapshot.zeroLargeBlobKeys()
		keys.zero()

		return appcredentials.InventoryReport{}, err
	}

	return r.buildCredentialInventoryReport(snapshot, permission, keys), nil
}

func grantCoversInventoryPermission(
	grantPermission protocol.Permission,
	inventoryPermission protocol.Permission,
) bool {
	if grantPermission&inventoryPermission == inventoryPermission {
		return true
	}

	return inventoryPermission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		grantPermission&protocol.PermissionCredentialManagement != 0
}

func (r Runner) readCredentialInventorySnapshot(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	token []byte,
) (credentialInventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseMetadata))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return credentialInventorySnapshot{}, err
	}

	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			credentialManagementCommand(info),
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if err := ctx.Err(); err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			credentialManagementCommand(info),
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if metadata.ExistingResidentCredentialsCount == nil ||
		metadata.MaxPossibleRemainingResidentCredentialsCount == nil {
		return credentialInventorySnapshot{}, failure.New(
			failure.CodeCTAPSpecViolation,
			failure.WithPhase(failure.PhaseMetadata),
		)
	}

	snapshot := credentialInventorySnapshot{
		info:     info,
		metadata: metadata,
	}
	complete := false
	defer func() {
		if !complete {
			snapshot.zeroLargeBlobKeys()
		}
	}()

	if *metadata.ExistingResidentCredentialsCount == 0 {
		complete = true

		return snapshot, nil
	}

	var rpTotal uint64

	for rpResponse, err := range device.EnumerateRPs(ctx, token) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}

		if err != nil {
			subCommand := protocol.CredentialManagementSubCommandEnumerateRPsBegin
			if len(snapshot.groups) > 0 {
				subCommand = protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP
			}

			return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				credentialManagementCommand(info),
				subCommand,
			))
		}

		if len(snapshot.groups) == 0 {
			rpTotal = uint64(rpResponse.TotalRPs)
		}

		snapshot.groups = append(snapshot.groups, credentialInventoryGroupSnapshot{rp: rpResponse})

		r.env.Events.Emit(ctx, model.OperationEvent{
			Stage:     model.OperationStageEnumeratingRPs,
			Completed: new(uint64(len(snapshot.groups))),
			Total:     &rpTotal,
		})
	}

	credentialsTotal := uint64(*metadata.ExistingResidentCredentialsCount)
	var credentialsCompleted uint64

	for groupIndex := range snapshot.groups {
		group := &snapshot.groups[groupIndex]
		if err := ctx.Err(); err != nil {
			return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				credentialManagementCommand(info),
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			))
		}

		for credentialResponse, err := range device.EnumerateCredentials(ctx, token, group.rp.RPIDHash) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}

			if err != nil {
				secret.Zero(credentialResponse.LargeBlobKey)

				subCommand := protocol.CredentialManagementSubCommandEnumerateCredentialsBegin
				if len(group.credentials) > 0 {
					subCommand = protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
				}

				return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
					failure.PhaseDiscovery,
					credentialManagementCommand(info),
					subCommand,
				))
			}

			group.credentials = append(group.credentials, credentialResponse)
			credentialsCompleted++

			r.env.Events.Emit(ctx, model.OperationEvent{
				Stage:     model.OperationStageEnumeratingCredentials,
				Completed: new(credentialsCompleted),
				Total:     &credentialsTotal,
			})
		}
	}

	complete = true

	return snapshot, nil
}

func (r Runner) buildCredentialInventoryReport(
	snapshot credentialInventorySnapshot,
	permission protocol.Permission,
	keys largeBlobKeyStore,
) appcredentials.InventoryReport {
	report := appcredentials.InventoryReport{
		Device: r.env.Selected,
		Support: appcredentials.SupportReport{
			CredentialManagement: true,
			PreviewOnly:          snapshot.info.Versions.IsPreviewOnly(),
			ReadOnlyPermission:   permission == protocol.PermissionPersistentCredentialManagementReadOnly,
		},
		Summary: appcredentials.InventorySummary{
			ExistingResidentCredentialsCount:             *snapshot.metadata.ExistingResidentCredentialsCount,
			MaxPossibleRemainingResidentCredentialsCount: *snapshot.metadata.MaxPossibleRemainingResidentCredentialsCount,
		},
		Groups: make([]appcredentials.CredentialGroup, 0, len(snapshot.groups)),
	}

	for _, rawGroup := range snapshot.groups {
		group := appcredentials.CredentialGroup{
			RPID:        strings.TrimSpace(rawGroup.rp.RP.ID),
			RPName:      strings.TrimSpace(rawGroup.rp.RP.Name),
			RPIDHashHex: hex.EncodeToString(rawGroup.rp.RPIDHash),
			Credentials: make([]appcredentials.CredentialRecord, 0, len(rawGroup.credentials)),
		}

		for _, response := range rawGroup.credentials {
			credentialIDHex := hex.EncodeToString(response.CredentialID.ID)
			record := appcredentials.CredentialRecord{
				CredentialIDHex:      credentialIDHex,
				CredentialType:       string(response.CredentialID.Type),
				CredentialTransports: credentialTransports(response.CredentialID.Transports),
				UserIDHex:            hex.EncodeToString(response.User.ID),
				UserName:             strings.TrimSpace(response.User.Name),
				DisplayName:          strings.TrimSpace(response.User.DisplayName),
				CredProtect:          response.CredProtect,
				ThirdPartyPayment:    response.ThirdPartyPayment,
				LargeBlobKeyState:    "missing",
			}

			if len(response.LargeBlobKey) > 0 {
				record.LargeBlobKeyState = "available"
				if keys == nil {
					secret.Zero(response.LargeBlobKey)
				} else {
					keys.add(group.RPIDHashHex, credentialIDHex, response.LargeBlobKey)
				}
			}

			group.Credentials = append(group.Credentials, record)
			report.Summary.TotalCredentials++
		}

		report.Groups = append(report.Groups, group)
	}

	sortInventoryGroups(report.Groups)
	report.Summary.TotalRPs = uint(len(report.Groups))

	return report
}

func credentialManagementCommand(info protocol.AuthenticatorGetInfoResponse) protocol.Command {
	if info.Versions.IsPreviewOnly() {
		return protocol.PrototypeAuthenticatorCredentialManagement
	}

	return protocol.AuthenticatorCredentialManagement
}

func inventoryPermission(info protocol.AuthenticatorGetInfoResponse) (protocol.Permission, error) {
	if !supportsCredentialManagement(info) {
		return 0, failure.New(failure.CodeCredentialManagementUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	if info.Options[protocol.OptionPersistentCredentialManagementReadOnly] {
		return protocol.PermissionPersistentCredentialManagementReadOnly, nil
	}

	return protocol.PermissionCredentialManagement, nil
}

func supportsCredentialManagement(info protocol.AuthenticatorGetInfoResponse) bool {
	option := protocol.OptionCredentialManagement
	if info.Versions.IsPreviewOnly() {
		option = protocol.OptionCredentialManagementPreview
	}

	enabled, ok := info.Options[option]

	return ok && enabled
}

func credentialTransports(transports []credential.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}

	return lo.Map(transports, func(transport credential.AuthenticatorTransport, _ int) string {
		return string(transport)
	})
}

func sortInventoryGroups(groups []appcredentials.CredentialGroup) {
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].RPID != groups[j].RPID {
			return groups[i].RPID < groups[j].RPID
		}

		if groups[i].RPName != groups[j].RPName {
			return groups[i].RPName < groups[j].RPName
		}

		return groups[i].RPIDHashHex < groups[j].RPIDHashHex
	})

	for i := range groups {
		sort.Slice(groups[i].Credentials, func(left, right int) bool {
			return groups[i].Credentials[left].CredentialIDHex < groups[i].Credentials[right].CredentialIDHex
		})
	}
}
