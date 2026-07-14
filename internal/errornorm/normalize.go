package errornorm

import (
	"context"
	"errors"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/model/failure"
)

// Normalize converts every non-nil error into a stable failure.Error. The
// requested public operation is supplied only at this boundary; annotations
// carry the lower-level phase and actual authenticator command instead.
func Normalize(err error, operation string) *failure.Error {
	ctx := annotatedContext(err)
	if existing, ok := errors.AsType[*failure.Error](err); ok {
		if operation != "" {
			existing.Operation = operation
		}
		if existing.Phase == "" {
			existing.Phase = ctx.phase
		}

		return existing
	}
	if errors.Is(err, context.Canceled) {
		return failure.Wrap(
			failure.CodeOperationCanceled,
			err,
			failureOptions(operation, ctx.phase, nil)...,
		)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure.Wrap(
			failure.CodeOperationTimeout,
			err,
			failureOptions(operation, ctx.phase, nil)...,
		)
	}

	if ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err); ok {
		return normalizeCTAP(err, ctapErr, operation, ctx)
	}

	if code, ok := upstreamCode(err, ctx); ok {
		return failure.Wrap(code, err, failureOptions(operation, ctx.phase, nil)...)
	}
	if code, ok := transportCode(err); ok {
		return failure.Wrap(code, err, failureOptions(operation, ctx.phase, nil)...)
	}

	return failure.Wrap(
		failure.CodeInternalError,
		err,
		failureOptions(operation, ctx.phase, nil)...,
	)
}

func normalizeCTAP(
	err error,
	ctapErr *ctaptransport.CTAPError,
	operation string,
	ctx errorContext,
) *failure.Error {
	ctx.command = ctapErr.Command
	if ctx.phase == "" {
		ctx.phase = failure.PhaseAuthenticatorCommand
	}
	if ctx.command == protocol.AuthenticatorGetNextAssertion {
		ctx.phase = failure.PhaseAssertionContinuation
	}

	detail := ctapDetail(ctapErr, ctx)

	return failure.Wrap(
		codeForCTAP(ctapErr.StatusCode, ctx),
		err,
		failureOptions(operation, ctx.phase, detail)...,
	)
}

func ctapDetail(ctapErr *ctaptransport.CTAPError, ctx errorContext) *failure.CTAPDetail {
	detail := &failure.CTAPDetail{
		CommandCode: uint8(ctx.command),
		StatusCode:  uint8(ctapErr.StatusCode),
	}
	if ctx.subCommand != 0 {
		subCommand := ctx.subCommand
		detail.SubCommandCode = &subCommand
	}

	return detail
}

func failureOptions(operation string, phase failure.Phase, detail *failure.CTAPDetail) []failure.Option {
	return []failure.Option{
		failure.WithOperation(operation),
		failure.WithPhase(phase),
		failure.WithCTAP(detail),
	}
}

func annotatedContext(err error) errorContext {
	if annotated, ok := err.(*annotatedError); ok {
		return annotated.ctx
	}

	return errorContext{}
}
