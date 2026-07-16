package service

import (
	"context"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func operationEnvelopeMeta(envelope operationEnvelope) OperationEnvelopeMeta {
	return OperationEnvelopeMeta{
		OperationID:   envelope.OperationID,
		SessionID:     envelope.SessionID,
		Kind:          envelope.Kind,
		SessionClosed: envelope.SessionClosed,
		Error:         envelope.Error,
	}
}

func runTypedOperation[T model.OperationResult](
	service *Service,
	ctx context.Context,
	req OperationRequest,
	operation model.Operation,
) (OperationEnvelopeMeta, *T, error) {
	envelope, err := service.runOperation(ctx, req, operation)
	if err != nil {
		return OperationEnvelopeMeta{}, nil, err
	}

	meta := operationEnvelopeMeta(envelope)
	result, typeErr := typedOperationResult[T](envelope)
	if typeErr != nil {
		return OperationEnvelopeMeta{}, nil, typeErr
	}

	return meta, result, nil
}

func typedOperationResult[T model.OperationResult](envelope operationEnvelope) (*T, error) {
	if envelope.Result == nil {
		return nil, nil
	}

	result, ok := envelope.Result.(T)
	if !ok {
		return nil, failure.New(failure.CodeInternalError,
			failure.WithOperation(string(envelope.Kind)),
			failure.WithPhase(failure.PhaseDecode),
		)
	}

	return &result, nil
}
