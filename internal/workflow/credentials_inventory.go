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
	return r.credentialInventoryReport(ctx, device, protocol.PermissionNone)
}

func (r Runner) credentialInventoryReport(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	grantPermission protocol.Permission,
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

	var report appcredentials.InventoryReport
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: grantPermission,
		ReplaySafe: true,
	}, func(token []byte) error {
		current, err := r.buildCredentialInventoryReport(ctx, device, token, permission)
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			zeroCredentialInventoryReport(&current)

			return errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
		}

		report = current

		return nil
	})
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	return report, nil
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

func (r Runner) buildCredentialInventoryReport(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	token []byte,
	permission protocol.Permission,
) (appcredentials.InventoryReport, error) {
	if err := ctx.Err(); err != nil {
		return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseMetadata))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			credentialManagementCommand(info),
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if err := ctx.Err(); err != nil {
		return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			credentialManagementCommand(info),
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if metadata.ExistingResidentCredentialsCount == nil ||
		metadata.MaxPossibleRemainingResidentCredentialsCount == nil {
		return appcredentials.InventoryReport{}, failure.New(
			failure.CodeCTAPSpecViolation,
			failure.WithPhase(failure.PhaseMetadata),
		)
	}

	report := appcredentials.InventoryReport{
		Device: r.env.Selected,
		Support: appcredentials.SupportReport{
			CredentialManagement: true,
			PreviewOnly:          info.Versions.IsPreviewOnly(),
			ReadOnlyPermission:   permission == protocol.PermissionPersistentCredentialManagementReadOnly,
		},
		Summary: appcredentials.InventorySummary{
			ExistingResidentCredentialsCount:             *metadata.ExistingResidentCredentialsCount,
			MaxPossibleRemainingResidentCredentialsCount: *metadata.MaxPossibleRemainingResidentCredentialsCount,
		},
	}
	completed := false
	defer func() {
		if !completed {
			zeroCredentialInventoryReport(&report)
		}
	}()

	if *metadata.ExistingResidentCredentialsCount == 0 {
		report.Groups = []appcredentials.CredentialGroup{}
		completed = true
		return report, nil
	}

	rpResponses := make([]protocol.AuthenticatorCredentialManagementResponse, 0)
	var rpTotal uint64

	for rpResponse, err := range device.EnumerateRPs(ctx, token) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}

		if err != nil {
			subCommand := protocol.CredentialManagementSubCommandEnumerateRPsBegin
			if len(rpResponses) > 0 {
				subCommand = protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP
			}

			return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				credentialManagementCommand(info),
				subCommand,
			))
		}

		if len(rpResponses) == 0 {
			rpTotal = uint64(rpResponse.TotalRPs)
		}

		rpResponses = append(rpResponses, rpResponse)

		r.env.Events.Emit(ctx, model.OperationEvent{
			Stage:     model.OperationStageEnumeratingRPs,
			Completed: new(uint64(len(rpResponses))),
			Total:     &rpTotal,
		})
	}

	report.Groups = make([]appcredentials.CredentialGroup, 0, len(rpResponses))
	credentialsTotal := uint64(*metadata.ExistingResidentCredentialsCount)

	for _, rpResponse := range rpResponses {
		if err := ctx.Err(); err != nil {
			return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				credentialManagementCommand(info),
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			))
		}

		report.Groups = append(report.Groups, appcredentials.CredentialGroup{
			RPID:        strings.TrimSpace(rpResponse.RP.ID),
			RPName:      strings.TrimSpace(rpResponse.RP.Name),
			RPIDHashHex: hex.EncodeToString(rpResponse.RPIDHash),
		})
		group := &report.Groups[len(report.Groups)-1]

		for credentialResponse, err := range device.EnumerateCredentials(ctx, token, rpResponse.RPIDHash) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}

			if err != nil {
				subCommand := protocol.CredentialManagementSubCommandEnumerateCredentialsBegin
				if len(group.Credentials) > 0 {
					subCommand = protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
				}

				return appcredentials.InventoryReport{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
					failure.PhaseDiscovery,
					credentialManagementCommand(info),
					subCommand,
				))
			}

			record := appcredentials.CredentialRecord{
				CredentialIDHex:      hex.EncodeToString(credentialResponse.CredentialID.ID),
				CredentialType:       string(credentialResponse.CredentialID.Type),
				CredentialTransports: credentialTransports(credentialResponse.CredentialID.Transports),
				UserIDHex:            hex.EncodeToString(credentialResponse.User.ID),
				UserName:             strings.TrimSpace(credentialResponse.User.Name),
				DisplayName:          strings.TrimSpace(credentialResponse.User.DisplayName),
				CredProtect:          credentialResponse.CredProtect,
				LargeBlobKey:         credentialResponse.LargeBlobKey,
				ThirdPartyPayment:    credentialResponse.ThirdPartyPayment,
			}

			if len(credentialResponse.LargeBlobKey) > 0 {
				record.LargeBlobKeyState = "available"
			} else {
				record.LargeBlobKeyState = "missing"
			}

			group.Credentials = append(group.Credentials, record)
			report.Summary.TotalCredentials++

			r.env.Events.Emit(ctx, model.OperationEvent{
				Stage:     model.OperationStageEnumeratingCredentials,
				Completed: new(uint64(report.Summary.TotalCredentials)),
				Total:     &credentialsTotal,
			})
		}

	}

	sortInventoryGroups(report.Groups)
	report.Summary.TotalRPs = uint(len(report.Groups))

	completed = true
	return report, nil
}

func zeroCredentialInventoryReport(report *appcredentials.InventoryReport) {
	for groupIndex := range report.Groups {
		for credentialIndex := range report.Groups[groupIndex].Credentials {
			secret.Zero(report.Groups[groupIndex].Credentials[credentialIndex].LargeBlobKey)
			report.Groups[groupIndex].Credentials[credentialIndex].LargeBlobKey = nil
		}
	}
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
