package workflow

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/samber/lo"
)

func (r Runner) bioSensorInfo(ctx context.Context) (appconfig.BioSensorReport, error) {
	return r.bioSensorReport(ctx)
}

func (r Runner) bioList(ctx context.Context) (appconfig.BioListReport, error) {
	status, err := r.configStatus(ctx)
	if err != nil {
		return appconfig.BioListReport{}, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionBioEnrollment, "")
	if err != nil {
		return appconfig.BioListReport{}, err
	}
	defer secret.Zero(token)

	return r.bioListReport(ctx, status, token)
}

func (r Runner) bioSensorReport(ctx context.Context) (appconfig.BioSensorReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioSensorReport{}, err
	}

	authenticator := r.bioEnrollmentManager()
	status := r.statusReport()
	if !status.Bio.Supported {
		return appconfig.BioSensorReport{}, fmt.Errorf("%w: device does not report bioEnroll support", appconfig.ErrBioUnsupported)
	}

	modality, err := authenticator.GetBioModality(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, ctaperrors.Annotate(err, ctaperrors.WithCommand(
			model.OperationBioSensorInfo,
			bioEnrollmentCommand(status),
			ctaperrors.DomainConfig,
		))
	}

	sensor, err := authenticator.GetFingerprintSensorInfo(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioSensorInfo,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo,
		))
	}

	report := appconfig.BioSensorReport{
		Device:      status.Device,
		Supported:   true,
		PreviewOnly: status.Bio.PreviewOnly,
	}
	if modality.Modality != nil {
		report.Modality = bioModality(*modality.Modality)
	}
	if sensor.FingerprintKind != nil {
		report.FingerprintKind = fingerprintKind(*sensor.FingerprintKind)
	}
	if sensor.MaxCaptureSamplesRequiredForEnroll != nil {
		report.MaxCaptureSamplesRequiredForEnroll = sensor.MaxCaptureSamplesRequiredForEnroll
	}
	if sensor.MaxTemplateFriendlyName != nil {
		report.MaxTemplateFriendlyName = sensor.MaxTemplateFriendlyName
	}

	return report, nil
}

func bioModality(value protocol.BioModality) *appconfig.BioModality {
	switch value {
	case protocol.BioModalityFingerprint:
		return new(appconfig.BioModalityFingerprint)
	default:
		return nil
	}
}

func fingerprintKind(value uint) *appconfig.FingerprintKind {
	switch value {
	case 1:
		return new(appconfig.FingerprintKindTouch)
	case 2:
		return new(appconfig.FingerprintKindSwipe)
	default:
		return nil
	}
}

func (r Runner) bioListReport(ctx context.Context, status appconfig.StatusReport, token []byte) (appconfig.BioListReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioListReport{}, err
	}

	if !status.Bio.Supported {
		return appconfig.BioListReport{}, fmt.Errorf("%w: device does not report bioEnroll support", appconfig.ErrBioUnsupported)
	}

	resp, err := r.bioEnrollmentManager().EnumerateEnrollments(ctx, token)
	if err != nil {
		return appconfig.BioListReport{}, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioList,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		))
	}

	records := lo.Map(resp.TemplateInfos, func(info protocol.TemplateInfo, _ int) appconfig.BioEnrollmentRecord {
		return appconfig.BioEnrollmentRecord{
			TemplateIDHex: hex.EncodeToString(info.TemplateID),
			FriendlyName:  info.TemplateFriendlyName,
		}
	})

	return appconfig.BioListReport{
		Device:      status.Device,
		Supported:   true,
		PreviewOnly: status.Bio.PreviewOnly,
		Enrollments: records,
	}, nil
}

func bioEnrollmentCommand(status appconfig.StatusReport) protocol.Command {
	if status.Bio.PreviewOnly {
		return protocol.PrototypeAuthenticatorBioEnrollment
	}

	return protocol.AuthenticatorBioEnrollment
}
