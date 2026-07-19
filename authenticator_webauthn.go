package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/webauthn"
)

func (a *Authenticator) MakeCredential(
	ctx context.Context,
	operation webauthn.MakeCredentialOperation,
	opts ...OperationOption,
) (*webauthn.MakeCredentialOutput, error) {
	return executeOperation(a, ctx, model.OperationMakeCredential, func(runner workflow.Runner, ctx context.Context) (webauthn.MakeCredentialOutput, error) {
		return runner.MakeCredential(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) GetAssertion(
	ctx context.Context,
	operation webauthn.GetAssertionOperation,
	opts ...OperationOption,
) (*webauthn.GetAssertionOutput, error) {
	return executeOperation(a, ctx, model.OperationGetAssertion, func(runner workflow.Runner, ctx context.Context) (webauthn.GetAssertionOutput, error) {
		return runner.GetAssertion(ctx, a.device, operation)
	}, opts...)
}
