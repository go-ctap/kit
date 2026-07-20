package workflow

import (
	"context"
	"encoding/hex"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/samber/lo"
)

func (r Runner) BioList(ctx context.Context, device BioDevice) (appconfig.BioListReport, error) {
	status, err := r.statusWithRetries(ctx, device)
	if err != nil {
		return appconfig.BioListReport{}, err
	}

	var report appconfig.BioListReport
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
		ReplaySafe: true,
	}, func(token []byte) error {
		var err error
		report, err = r.bioListReport(ctx, device, status, token)

		return err
	})

	return report, err
}

func (r Runner) BioSensorInfo(ctx context.Context, device BioDevice) (appconfig.BioSensorReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioSensorReport{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)
	if !status.Bio.Supported {
		return appconfig.BioSensorReport{}, failure.New(failure.CodeBioUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	modality, err := device.GetBioModality(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
		))
	}

	sensor, err := device.GetFingerprintSensorInfo(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo,
		))
	}

	report := appconfig.BioSensorReport{
		Device:      status.Device,
		Supported:   true,
		PreviewOnly: status.Bio.PreviewOnly,
	}
	report.Modality = bioModality(modality.Modality)
	report.FingerprintKind = fingerprintKind(sensor.FingerprintKind)

	if sensor.MaxCaptureSamplesRequiredForEnroll != nil {
		report.MaxCaptureSamplesRequiredForEnroll = sensor.MaxCaptureSamplesRequiredForEnroll
	}

	if sensor.MaxTemplateFriendlyName != nil {
		report.MaxTemplateFriendlyName = sensor.MaxTemplateFriendlyName
	}

	return report, nil
}

func bioModality(value protocol.BioModality) appconfig.BioModality {
	switch value {
	case protocol.BioModalityFingerprint:
		return appconfig.BioModalityFingerprint
	default:
		return ""
	}
}

func fingerprintKind(value uint) appconfig.FingerprintKind {
	switch value {
	case 1:
		return appconfig.FingerprintKindTouch
	case 2:
		return appconfig.FingerprintKindSwipe
	default:
		return ""
	}
}

func (r Runner) bioListReport(
	ctx context.Context,
	device BioDevice,
	status appconfig.StatusReport,
	token []byte,
) (appconfig.BioListReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioListReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		))
	}

	if !status.Bio.Supported {
		return appconfig.BioListReport{}, failure.New(failure.CodeBioUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	resp, err := device.EnumerateEnrollments(ctx, token)
	if err != nil {
		return appconfig.BioListReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
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
