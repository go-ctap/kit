package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model"
)

type Runner struct {
	env Environment
}

func NewRunner(env Environment) Runner {
	return Runner{env: env}
}

func (r Runner) Inspect(ctx context.Context) (model.InspectOutput, error) {
	result, err := r.inspect(ctx)

	return model.InspectOutput{Result: result}, err
}

func (r Runner) ListCredentials(ctx context.Context) (model.CredentialsOutput, error) {
	result, err := r.credentialInventoryReport(ctx, protocol.PermissionNone)

	return model.CredentialsOutput{Report: result}, err
}

func (r Runner) CredentialStoreState(ctx context.Context) (model.CredentialStoreStateOutput, error) {
	result, err := r.credentialStoreState(ctx)

	return model.CredentialStoreStateOutput{Result: result}, err
}

func (r Runner) DeleteCredential(
	ctx context.Context,
	operation model.DeleteCredentialOperation,
) (model.CredentialDeleteOutput, error) {
	return r.deleteCredential(ctx, operation)
}

func (r Runner) UpdateCredentialUser(
	ctx context.Context,
	operation model.UpdateCredentialUserOperation,
) (model.CredentialUpdateOutput, error) {
	return r.updateCredentialUser(ctx, operation)
}

func (r Runner) ReadLargeBlob(
	ctx context.Context,
	operation model.ReadLargeBlobOperation,
) (model.LargeBlobReadOutput, error) {
	result, err := r.readLargeBlob(ctx, operation)

	return model.LargeBlobReadOutput{Report: result}, err
}

func (r Runner) ListLargeBlobs(ctx context.Context) (model.LargeBlobListOutput, error) {
	result, err := r.listLargeBlobs(ctx, model.ListLargeBlobsOperation{})

	return model.LargeBlobListOutput{Report: result}, err
}

func (r Runner) WriteLargeBlob(
	ctx context.Context,
	operation model.WriteLargeBlobOperation,
) (model.LargeBlobMutationOutput, error) {
	return r.writeLargeBlob(ctx, operation)
}

func (r Runner) DeleteLargeBlob(
	ctx context.Context,
	operation model.DeleteLargeBlobOperation,
) (model.LargeBlobMutationOutput, error) {
	return r.deleteLargeBlob(ctx, operation)
}

func (r Runner) GarbageCollectLargeBlobs(
	ctx context.Context,
	operation model.GarbageCollectLargeBlobsOperation,
) (model.LargeBlobMutationOutput, error) {
	return r.garbageCollectLargeBlobs(ctx, operation)
}

func (r Runner) ConfigStatus(ctx context.Context) (model.ConfigStatusOutput, error) {
	result, err := r.statusWithRetries(ctx)

	return model.ConfigStatusOutput{Report: result}, err
}

func (r Runner) SetPIN(
	ctx context.Context,
	operation model.SetPINOperation,
) (model.PINOutput, error) {
	return r.setPIN(ctx, operation)
}

func (r Runner) ChangePIN(
	ctx context.Context,
	operation model.ChangePINOperation,
) (model.PINOutput, error) {
	return r.changePIN(ctx, operation)
}

func (r Runner) SetAlwaysUV(
	ctx context.Context,
	operation model.SetAlwaysUVOperation,
) (model.AuthenticatorConfigOutput, error) {
	return r.setAlwaysUV(ctx, operation)
}

func (r Runner) SetMinPINLength(
	ctx context.Context,
	operation model.SetMinPINLengthOperation,
) (model.AuthenticatorConfigOutput, error) {
	return r.setMinPINLength(ctx, operation)
}

func (r Runner) EnableLongTouchForReset(
	ctx context.Context,
	operation model.EnableLongTouchForResetOperation,
) (model.AuthenticatorConfigOutput, error) {
	return r.enableLongTouchForReset(ctx, operation)
}

func (r Runner) BioSensorInfo(ctx context.Context) (model.BioSensorOutput, error) {
	result, err := r.bioSensorReport(ctx)

	return model.BioSensorOutput{Report: result}, err
}

func (r Runner) BioList(ctx context.Context) (model.BioListOutput, error) {
	result, err := r.bioList(ctx)

	return model.BioListOutput{Report: result}, err
}

func (r Runner) BioEnroll(
	ctx context.Context,
	operation model.BioEnrollOperation,
) (model.BioEnrollOutput, error) {
	return r.enrollBio(ctx, operation)
}

func (r Runner) BioRename(
	ctx context.Context,
	operation model.BioRenameOperation,
) (model.BioMutationOutput, error) {
	return r.renameBio(ctx, operation)
}

func (r Runner) BioRemove(
	ctx context.Context,
	operation model.BioRemoveOperation,
) (model.BioMutationOutput, error) {
	return r.removeBio(ctx, operation)
}

func (r Runner) ResetFactory(
	ctx context.Context,
	operation model.ResetFactoryOperation,
) (model.ResetFactoryOutput, error) {
	return r.resetFactory(ctx, operation)
}

func (r Runner) MakeCredential(
	ctx context.Context,
	operation model.MakeCredentialOperation,
) (model.MakeCredentialOutput, error) {
	return r.makeCredential(ctx, operation)
}

func (r Runner) GetAssertion(
	ctx context.Context,
	operation model.GetAssertionOperation,
) (model.GetAssertionOutput, error) {
	return r.getAssertion(ctx, operation)
}
