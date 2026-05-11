package workflow

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/samber/lo"
)

func (r Runner) listCredentials(ctx context.Context) (appcredentials.InventoryReport, error) {
	if report, ok := r.env.Cache.Credential(); ok {
		return report, nil
	}

	report, err := r.readCredentialInventoryReport(ctx)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	return report, nil
}

func (r Runner) readCredentialInventoryReport(ctx context.Context) (appcredentials.InventoryReport, error) {
	report, ok := r.env.Cache.Credential()
	if ok {
		return report, nil
	}

	permission, err := inventoryPermission(r.infoProvider().GetInfo())
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), permission, "")
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}
	defer secret.Zero(token)

	report, err = r.buildCredentialInventoryReport(token, permission)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	r.env.Cache.SetCredential(report)
	return report, nil
}

func (r Runner) buildCredentialInventoryReport(token []byte, permission ctaptypes.Permission) (appcredentials.InventoryReport, error) {
	authenticator := r.credentialManager()
	info := authenticator.GetInfo()

	metadata, err := authenticator.GetCredsMetadata(token)
	if err != nil {
		return appcredentials.InventoryReport{}, ctaperrors.Annotate(err, ctaperrors.WithCredentialManagementSubCommand(
			model.OperationListCredentials,
			credentialManagementCommand(info),
			ctaptypes.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	report := appcredentials.InventoryReport{
		Device: r.env.Selected,
		Support: appcredentials.SupportReport{
			CredentialManagement: true,
			PreviewOnly:          info.Versions.IsPreviewOnly(),
			ReadOnlyPermission:   permission == ctaptypes.PermissionPersistentCredentialManagementReadOnly,
		},
		Summary: appcredentials.InventorySummary{
			ExistingResidentCredentialsCount:             metadata.ExistingResidentCredentialsCount,
			MaxPossibleRemainingResidentCredentialsCount: metadata.MaxPossibleRemainingResidentCredentialsCount,
		},
	}

	rpResponses := make([]ctaptypes.AuthenticatorCredentialManagementResponse, 0)
	var rpTotal uint64

	for rpResponse, err := range authenticator.EnumerateRPs(token) {
		if err != nil {
			return appcredentials.InventoryReport{}, ctaperrors.Annotate(err, ctaperrors.WithCredentialManagementSubCommand(
				model.OperationListCredentials,
				credentialManagementCommand(info),
				ctaptypes.CredentialManagementSubCommandEnumerateRPsBegin,
			))
		}

		if rpTotal == 0 {
			rpTotal = uint64(rpResponse.TotalRPs)
		}

		rpResponses = append(rpResponses, rpResponse)

		r.env.Events.Emit(model.OperationEvent{
			Stage:     model.OperationStageEnumeratingRPs,
			Completed: new(uint64(len(rpResponses))),
			Total:     &rpTotal,
		})
	}

	groups := make([]appcredentials.CredentialGroup, 0, len(rpResponses))
	credentialsTotal := uint64(metadata.ExistingResidentCredentialsCount)

	for _, rpResponse := range rpResponses {
		group := appcredentials.CredentialGroup{
			RPID:        strings.TrimSpace(rpResponse.RP.ID),
			RPName:      strings.TrimSpace(rpResponse.RP.Name),
			RPIDHashHex: hex.EncodeToString(rpResponse.RPIDHash),
		}

		for credentialResponse, err := range authenticator.EnumerateCredentials(token, rpResponse.RPIDHash) {
			if err != nil {
				return appcredentials.InventoryReport{}, ctaperrors.Annotate(err, ctaperrors.WithCredentialManagementSubCommand(
					model.OperationListCredentials,
					credentialManagementCommand(info),
					ctaptypes.CredentialManagementSubCommandEnumerateCredentialsBegin,
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
				LargeBlobKey:         slices.Clone(credentialResponse.LargeBlobKey),
				ThirdPartyPayment:    credentialResponse.ThirdPartyPayment,
			}
			if len(credentialResponse.LargeBlobKey) > 0 {
				record.LargeBlobKeyState = "available"
			} else {
				record.LargeBlobKeyState = "missing"
			}

			group.Credentials = append(group.Credentials, record)
			report.Summary.TotalCredentials++

			r.env.Events.Emit(model.OperationEvent{
				Stage:     model.OperationStageEnumeratingCredentials,
				Completed: new(uint64(report.Summary.TotalCredentials)),
				Total:     &credentialsTotal,
			})
		}

		groups = append(groups, group)
	}

	sortInventoryGroups(groups)
	report.Groups = groups
	report.Summary.TotalRPs = uint(len(groups))

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

func credentialManagementCommand(info ctaptypes.AuthenticatorGetInfoResponse) ctaptypes.Command {
	if info.Versions.IsPreviewOnly() {
		return ctaptypes.PrototypeAuthenticatorCredentialManagement
	}

	return ctaptypes.AuthenticatorCredentialManagement
}

func inventoryPermission(info ctaptypes.AuthenticatorGetInfoResponse) (ctaptypes.Permission, error) {
	if !supportsCredentialManagement(info) {
		return 0, fmt.Errorf("%w: device does not support resident credential management", appcredentials.ErrUnsupportedCredentialManagement)
	}

	if info.Options[ctaptypes.OptionCredentialManagementReadOnly] {
		return ctaptypes.PermissionPersistentCredentialManagementReadOnly, nil
	}

	return ctaptypes.PermissionCredentialManagement, nil
}

func supportsCredentialManagement(info ctaptypes.AuthenticatorGetInfoResponse) bool {
	option := ctaptypes.OptionCredentialManagement
	if info.Versions.IsPreviewOnly() {
		option = ctaptypes.OptionCredentialManagementPreview
	}

	enabled, ok := info.Options[option]

	return ok && enabled
}

func credentialTransports(transports []webauthntypes.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}

	return lo.Map(transports, func(transport webauthntypes.AuthenticatorTransport, _ int) string {
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
