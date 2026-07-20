package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	appoperation "github.com/go-ctap/kit/model/operation"
	"github.com/go-ctap/kit/model/webauthn"
)

func (a *Authenticator) MakeCredential(
	ctx context.Context,
	operation webauthn.MakeCredentialOperation,
	opts ...OperationOption,
) (*webauthn.MakeCredentialOutput, error) {
	return executeOperation(a, ctx, appoperation.MakeCredential, func(runner workflow.Runner, ctx context.Context) (webauthn.MakeCredentialOutput, error) {
		return runner.MakeCredential(ctx, a.webAuthn, operation)
	}, opts...)
}

func (a *Authenticator) GetAssertion(
	ctx context.Context,
	operation webauthn.GetAssertionOperation,
	opts ...OperationOption,
) (*webauthn.GetAssertionOutput, error) {
	return executeOperation(a, ctx, appoperation.GetAssertion, func(runner workflow.Runner, ctx context.Context) (webauthn.GetAssertionOutput, error) {
		return runner.GetAssertion(ctx, a.webAuthn, operation)
	}, opts...)
}
