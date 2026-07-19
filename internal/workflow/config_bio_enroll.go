package workflow

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

const bioEnrollmentCancelTimeout = 2 * time.Second

func (r Runner) BioEnroll(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioEnrollOperation,
) (appconfig.BioEnrollOutput, error) {
	var output appconfig.BioEnrollOutput

	status := rtconfig.BuildStatusReport(r.env.Selected, device.GetInfo())

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioEnrollPreview(status, req.TimeoutMilliseconds, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		result, err := r.runBioEnrollment(
			ctx,
			device,
			appconfig.BioEnrollRequest{
				TimeoutMilliseconds: req.TimeoutMilliseconds,
			},
			preview,
			token,
		)
		output.Result = &result

		return err
	})

	return output, err
}

func (r Runner) bioEnrollmentProgress(ctx context.Context) rtconfig.BioEnrollProgress {
	var completed uint64

	return func(sample appconfig.BioEnrollSample) error {
		completed++
		event := model.OperationEvent{
			Stage:        model.OperationStageCapturingBioSample,
			Completed:    new(completed),
			SampleStatus: sample.Status,
		}

		if sample.RemainingSamples != nil {
			total := completed + uint64(*sample.RemainingSamples)
			event.Total = new(total)
		}
		r.env.Events.Emit(ctx, event)

		return nil
	}
}

func (r Runner) runBioEnrollment(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioEnrollRequest,
	preview appconfig.BioEnrollPreview,
	token []byte,
) (appconfig.BioEnrollResult, error) {
	progress := r.bioEnrollmentProgress(ctx)
	result := appconfig.BioEnrollResult{
		DeviceFingerprint: preview.Device.Fingerprint,
		PreviewOnly:       preview.PreviewOnly,
	}

	cancelAfterFailure := func(cause error) (appconfig.BioEnrollResult, error) {
		result.CancelAttempted = true

		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bioEnrollmentCancelTimeout)
		defer cancel()
		cancelErr := device.CancelCurrentEnrollment(cancelCtx)
		if cancelErr == nil {
			result.CancelSucceeded = true
		}

		return result, cause
	}

	recordSample := func(resp protocol.AuthenticatorBioEnrollmentResponse) error {
		if len(resp.TemplateID) > 0 {
			result.TemplateIDHex = hex.EncodeToString(resp.TemplateID)
		}

		if resp.LastEnrollSampleStatus != nil {
			result.LastEnrollSampleStatus = resp.LastEnrollSampleStatus.String()
		}
		result.RemainingSamples = snapshotPtr(resp.RemainingSamples)
		sample := appconfig.BioEnrollSample{
			Status:           result.LastEnrollSampleStatus,
			RemainingSamples: result.RemainingSamples,
		}

		result.Samples = append(result.Samples, sample)

		if progress != nil {
			return progress(sample)
		}

		return nil
	}

	begin, err := device.EnrollBegin(ctx, token, req.TimeoutMilliseconds)
	if err != nil {
		return appconfig.BioEnrollResult{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(rtconfig.BuildStatusReport(r.env.Selected, device.GetInfo())),
			protocol.BioEnrollmentSubCommandEnrollBegin,
		))
	}

	if err := recordSample(begin); err != nil {
		return cancelAfterFailure(err)
	}

	for result.RemainingSamples != nil && *result.RemainingSamples > 0 {
		if err := ctx.Err(); err != nil {
			return cancelAfterFailure(errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
				failure.PhaseAuthenticatorCommand,
				bioEnrollmentCommand(rtconfig.BuildStatusReport(r.env.Selected, device.GetInfo())),
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		next, err := device.EnrollCaptureNextSample(ctx, token, begin.TemplateID, req.TimeoutMilliseconds)
		if err != nil {
			return cancelAfterFailure(errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
				failure.PhaseAuthenticatorCommand,
				bioEnrollmentCommand(rtconfig.BuildStatusReport(r.env.Selected, device.GetInfo())),
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		if err := recordSample(next); err != nil {
			return cancelAfterFailure(err)
		}
	}

	return result, nil
}
