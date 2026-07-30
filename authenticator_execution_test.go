package ctapkit

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/kit/internal/workflow"
	appoperation "github.com/go-ctap/kit/model/operation"
)

func TestExecuteSerializedOperationEnforcesZeroResultOnWorkflowFailure(t *testing.T) {
	session := openContractAuthenticator(t, nil, nil)
	defer func() { _ = session.Close() }()

	type result struct {
		Value string
	}

	cause := errors.New("workflow failed after producing a result")
	got, err := executeSerializedOperation(
		session.Authenticator,
		context.Background(),
		appoperation.ConfigStatus,
		operationConfig{},
		func(workflow.Runner, context.Context) (result, error) {
			return result{Value: "partial"}, cause
		},
	)
	if !errors.Is(err, cause) {
		t.Fatalf("executeSerializedOperation error = %v, want %v", err, cause)
	}
	requireZero(t, got)
}
