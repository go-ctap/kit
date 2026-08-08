package workflow

import (
	"context"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
)

// RunCTAP23Conformance executes the selected CTAP 2.3 tests over the opened
// authenticator's raw command boundary while routing tokens and resets through
// the owning runtime.
func (r Runner) RunCTAP23Conformance(
	ctx context.Context,
	cbor ctaptransport.CBOR,
	device ConfigDevice,
	tokenDevice rtauthenticator.TokenProvider,
	request ctap23.RunRequest,
) (conformance.SuiteResult, error) {
	suite, err := ctap23.SuiteFor(request.Mode, ctap23.Config{
		Metadata: request.Metadata,
		PersistentTokenProvider: func(
			ctx context.Context,
			_ *client.Client,
			permission protocol.Permission,
		) ([]byte, error) {
			return r.conformanceToken(ctx, device, tokenDevice, permission)
		},
		Resetter: func(ctx context.Context, _ *client.Client) error {
			return r.conformanceReset(ctx, device)
		},
	})
	if err != nil {
		return conformance.SuiteResult{}, err
	}

	runner, err := conformance.NewRunner(cbor)
	if err != nil {
		return conformance.SuiteResult{}, err
	}

	return runner.Run(ctx, suite)
}

func (r Runner) conformanceToken(
	ctx context.Context,
	device ConfigDevice,
	tokenDevice rtauthenticator.TokenProvider,
	permission protocol.Permission,
) ([]byte, error) {
	token, err := r.acquireConformanceToken(ctx, permission)
	if !failure.IsCode(err, failure.CodePINNotConfigured) {
		return token, err
	}

	response, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Message:    "Create a temporary PIN for CTAP 2.3 conformance testing.",
		Permission: permission.String(),
	})
	if err != nil {
		return nil, err
	}
	defer secret.Zero(response.PIN)

	err = device.SetPIN(ctx, string(response.PIN))
	r.env.Tokens.Invalidate()
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandSetPIN,
		))
	}

	token, err = tokenDevice.GetPinUvAuthTokenUsingPIN(
		ctx,
		string(response.PIN),
		permission,
		"",
	)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseTokenAcquisition,
			protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		))
	}

	return token, nil
}

func (r Runner) acquireConformanceToken(
	ctx context.Context,
	permission protocol.Permission,
) ([]byte, error) {
	var token []byte
	err := r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: permission,
	}, func(value []byte) error {
		token = slices.Clone(value)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r Runner) conformanceReset(ctx context.Context, device ConfigDevice) error {
	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + string(r.env.Selected.Attachment.ID) + " to continue the destructive conformance reset.",
		Destructive: true,
	}); err != nil {
		return err
	}

	r.recordStateEffect(rtruntime.StateEffectAuthenticatorReset)
	err := device.Reset(ctx)
	r.env.Tokens.Invalidate()
	if err != nil {
		return errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}

	return nil
}
