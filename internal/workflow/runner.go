package workflow

import (
	"context"
	"errors"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type Runner struct {
	env Environment
}

func (r Runner) infoProvider() authenticator.InfoProvider {
	return r.env.Authenticator
}

func (r Runner) tokenProvider() authenticator.TokenProvider {
	return r.env.Authenticator
}

func (r Runner) credentialManager() authenticator.CredentialManager {
	return r.env.Authenticator
}

func (r Runner) webAuthnManager() authenticator.WebAuthnManager {
	return r.env.Authenticator
}

func (r Runner) largeBlobManager() authenticator.LargeBlobManager {
	return r.env.Authenticator
}

func (r Runner) configManager() authenticator.ConfigManager {
	return r.env.Authenticator
}

func (r Runner) bioEnrollmentManager() authenticator.BioEnrollmentManager {
	return r.env.Authenticator
}

func Run(
	ctx context.Context,
	env Environment,
	operation model.Operation,
) (model.OperationResult, error) {
	return Runner{env: env}.runOperation(ctx, operation)
}

func (r Runner) runOperation(ctx context.Context, operation model.Operation) (model.OperationResult, error) {
	result, err := r.runOperationBody(ctx, operation)
	if err == nil || hasCommittedPartialResult(result.Output) {
		result.Effects.Apply(r.env.Cache)
	}

	return result.Output, err
}

func hasCommittedPartialResult(output model.OperationResult) bool {
	result, ok := output.(model.MakeCredentialOutput)

	return ok && result.Result != nil
}

type operationResult struct {
	Output  model.OperationResult
	Effects Effects
}

func outputOnly(output model.OperationResult) operationResult {
	return operationResult{Output: output}
}

func (r Runner) runWithOptionalToken(
	ctx context.Context,
	permission protocol.Permission,
	rpID string,
	run func([]byte) error,
) error {
	// High-level ctap methods complete authorization preflight before sending
	// the authenticator command, so this retry cannot repeat a mutation.
	err := run(nil)
	if !errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired) &&
		!errors.Is(err, ctapdevice.ErrBuiltInUVRequired) {
		return err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), permission, rpID)
	if err != nil {
		return err
	}
	defer secret.Zero(token)

	return run(token)
}

func (r Runner) runMutationWithOptionalToken(
	ctx context.Context,
	permission protocol.Permission,
	rpID string,
	run func([]byte) error,
	commandFinished func(),
) error {
	err := run(nil)
	if !errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired) &&
		!errors.Is(err, ctapdevice.ErrBuiltInUVRequired) {
		commandFinished()

		return err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), permission, rpID)
	if err != nil {
		return err
	}
	defer secret.Zero(token)

	err = run(token)
	commandFinished()

	return err
}

func (r Runner) runOperationBody(ctx context.Context, operation model.Operation) (operationResult, error) {
	switch req := operation.(type) {
	case model.InspectOperation:
		result, err := r.inspect(ctx)

		return outputOnly(model.InspectOutput{Result: result}), err
	case model.ListCredentialsOperation:
		result, err := r.listCredentials(ctx, req)

		return outputOnly(model.CredentialsOutput{Report: result}), err
	case model.CredentialStoreStateOperation:
		result, err := r.credentialStoreState(ctx)

		return outputOnly(model.CredentialStoreStateOutput{Result: result}), err
	case model.ReadLargeBlobOperation:
		result, err := r.readLargeBlob(ctx, req)

		return outputOnly(model.LargeBlobReadOutput{Report: result}), err
	case model.ListLargeBlobsOperation:
		result, err := r.listLargeBlobs(ctx, req)

		return outputOnly(model.LargeBlobListOutput{Report: result}), err
	case model.ConfigStatusOperation:
		result, err := r.configStatus(ctx)

		return outputOnly(model.ConfigStatusOutput{Report: result}), err
	case model.BioSensorInfoOperation:
		result, err := r.bioSensorInfo(ctx)

		return outputOnly(model.BioSensorOutput{Report: result}), err
	case model.BioListOperation:
		result, err := r.bioList(ctx)

		return outputOnly(model.BioListOutput{Report: result}), err
	case model.DeleteCredentialOperation:
		result, err := r.deleteCredential(ctx, req)

		return operationResult{Output: result, Effects: credentialMutationEffects(req)}, err
	case model.UpdateCredentialUserOperation:
		result, err := r.updateCredentialUser(ctx, req)

		return operationResult{Output: result, Effects: credentialMutationEffects(req)}, err
	case model.MakeCredentialOperation:
		result, err := r.makeCredential(ctx, req)

		return operationResult{Output: result, Effects: makeCredentialEffects(req, result)}, err
	case model.GetAssertionOperation:
		result, err := r.getAssertion(ctx, req)

		return operationResult{Output: result, Effects: getAssertionEffects(req, result)}, err
	case model.WriteLargeBlobOperation:
		result, err := r.writeLargeBlob(ctx, req)

		return operationResult{Output: result, Effects: largeBlobMutationResultEffects(req, result)}, err
	case model.DeleteLargeBlobOperation:
		result, err := r.deleteLargeBlob(ctx, req)

		return operationResult{Output: result, Effects: largeBlobMutationResultEffects(req, result)}, err
	case model.GarbageCollectLargeBlobsOperation:
		result, err := r.garbageCollectLargeBlobs(ctx, req)

		return operationResult{Output: result, Effects: largeBlobMutationResultEffects(req, result)}, err
	case model.ResetFactoryOperation:
		result, err := r.resetFactory(ctx, req)

		return operationResult{Output: result, Effects: resetEffects(req)}, err
	case model.SetPINOperation:
		result, err := r.setPIN(ctx, req)

		return operationResult{Output: result, Effects: pinMutationEffects(req)}, err
	case model.ChangePINOperation:
		result, err := r.changePIN(ctx, req)

		return operationResult{Output: result, Effects: pinMutationEffects(req)}, err
	case model.BioEnrollOperation:
		result, err := r.enrollBio(ctx, req)

		return operationResult{Output: result, Effects: bioMutationEffects(req)}, err
	case model.BioRenameOperation:
		result, err := r.renameBio(ctx, req)

		return operationResult{Output: result, Effects: Effects{}}, err
	case model.BioRemoveOperation:
		result, err := r.removeBio(ctx, req)

		return operationResult{Output: result, Effects: bioMutationEffects(req)}, err
	case model.SetAlwaysUVOperation:
		result, err := r.setAlwaysUV(ctx, req)

		return operationResult{Output: result, Effects: authenticatorConfigEffects(req)}, err
	case model.SetMinPINLengthOperation:
		result, err := r.setMinPINLength(ctx, req)

		return operationResult{Output: result, Effects: authenticatorConfigEffects(req)}, err
	case model.EnableLongTouchForResetOperation:
		result, err := r.enableLongTouchForReset(ctx, req)

		return operationResult{Output: result, Effects: authenticatorConfigEffects(req)}, err
	default:
		return operationResult{}, failure.New(failure.CodeOperationUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
}
