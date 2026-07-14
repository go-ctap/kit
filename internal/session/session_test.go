package session

import (
	"context"
	"testing"
	"time"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
)

func TestCloseCancelsActiveSerializedWorkflow(t *testing.T) {
	core := New(report.DeviceReport{}, nil, nil, false)
	entered := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := core.RunSerializedWorkflow(context.Background(), func(ctx context.Context) (model.OperationResult, error) {
			close(entered)
			<-ctx.Done()

			return nil, ctx.Err()
		})
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("workflow did not start")
	}

	core.markClosedAndCancelActive()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected active workflow to be canceled")
		}
	case <-time.After(time.Second):
		t.Fatal("workflow was not canceled by close")
	}
}
