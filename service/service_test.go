package service

import "testing"

func TestCancelSessionOperationCancelsOnlyThatSessionOperation(t *testing.T) {
	service := New()
	firstOperationID := OperationID("operation-1")
	secondOperationID := OperationID("operation-2")
	firstCanceled := false
	secondCanceled := false
	service.operations[firstOperationID] = &operationState{
		id:        firstOperationID,
		sessionID: "session-1",
		cancel:    func() { firstCanceled = true },
		done:      make(chan struct{}),
	}
	service.operations[secondOperationID] = &operationState{
		id:        secondOperationID,
		sessionID: "session-2",
		cancel:    func() { secondCanceled = true },
		done:      make(chan struct{}),
	}

	if !service.cancelSessionOperations("session-1") {
		t.Fatal("cancelSessionOperations returned false")
	}
	if !firstCanceled {
		t.Fatal("first session operation was not canceled")
	}
	if secondCanceled {
		t.Fatal("second session operation was canceled")
	}
}
