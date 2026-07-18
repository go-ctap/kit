package workflow

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

const bioEnrollmentCancelTimeout = 2 * time.Second

func (r Runner) enrollBio(ctx context.Context, req model.BioEnrollOperation) (model.OperationResult, error) {
	var output model.BioEnrollOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := appconfig.BuildBioEnrollPreview(status, req.TimeoutMilliseconds, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Start biometric enrollment on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.env.Authenticator, protocol.PermissionBioEnrollment, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	result, err := r.runBioEnrollment(
		ctx,
		appconfig.BioEnrollRequest{
			TimeoutMilliseconds: req.TimeoutMilliseconds,
			Confirmed:           true,
		},
		preview,
		token,
	)
	output.Result = &result
	return output, err
}

func (r Runner) bioEnrollmentProgress() appconfig.BioEnrollProgress {
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
		r.env.Events.Emit(event)

		return nil
	}
}

func (r Runner) runBioEnrollment(
	ctx context.Context,
	req appconfig.BioEnrollRequest,
	preview appconfig.BioEnrollPreview,
	token []byte,
) (appconfig.BioEnrollResult, error) {
	authenticator := r.env.Authenticator
	progress := r.bioEnrollmentProgress()
	result := appconfig.BioEnrollResult{
		DeviceFingerprint: preview.Device.Fingerprint,
		PreviewOnly:       preview.PreviewOnly,
	}

	cancelAfterFailure := func(cause error) (appconfig.BioEnrollResult, error) {
		result.CancelAttempted = true

		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bioEnrollmentCancelTimeout)
		defer cancel()
		cancelErr := authenticator.CancelCurrentEnrollment(cancelCtx)
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

	begin, err := authenticator.EnrollBegin(ctx, token, req.TimeoutMilliseconds)
	if err != nil {
		return appconfig.BioEnrollResult{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())),
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
				bioEnrollmentCommand(appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())),
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		next, err := authenticator.EnrollCaptureNextSample(ctx, token, begin.TemplateID, req.TimeoutMilliseconds)
		if err != nil {
			return cancelAfterFailure(errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
				failure.PhaseAuthenticatorCommand,
				bioEnrollmentCommand(appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())),
				protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
			)))
		}

		if err := recordSample(next); err != nil {
			return cancelAfterFailure(err)
		}
	}

	return result, nil
}
