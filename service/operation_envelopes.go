package service

import (
	"context"
	"fmt"

	"github.com/go-ctap/kit/model"
)

func operationEnvelopeMeta(envelope operationEnvelope) OperationEnvelopeMeta {
	return OperationEnvelopeMeta{
		OperationID: envelope.OperationID,
		SessionID:   envelope.SessionID,
		Kind:        envelope.Kind,
		Error:       envelope.Error,
	}
}

func runTypedOperation[T model.OperationResult](
	service *Service,
	ctx context.Context,
	req OperationRequest,
	operation model.Operation,
) (OperationEnvelopeMeta, *T, error) {
	envelope, err := service.runOperation(ctx, req, operation)
	meta := operationEnvelopeMeta(envelope)
	result, typeErr := typedOperationResult[T](envelope)
	if err != nil {
		return meta, result, err
	}

	return meta, result, typeErr
}

func typedOperationResult[T model.OperationResult](envelope operationEnvelope) (*T, error) {
	if envelope.Result == nil {
		return nil, nil
	}

	result, ok := envelope.Result.(T)
	if !ok {
		return nil, fmt.Errorf("ctapkit: operation %q returned %T", envelope.Kind, envelope.Result)
	}

	return &result, nil
}
