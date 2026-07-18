package transport

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func TestTransportErrors(t *testing.T) {
	failureCause := errors.New("device disconnected")
	proxyCause := errors.New("proxy unavailable")
	tests := []struct {
		name      string
		err       error
		normalize func(error) error
		code      failure.Code
	}{
		{
			name:      "canceled",
			err:       context.Canceled,
			normalize: transportError,
			code:      failure.CodeOperationCanceled,
		},
		{
			name:      "deadline",
			err:       context.DeadlineExceeded,
			normalize: transportError,
			code:      failure.CodeOperationTimeout,
		},
		{
			name:      "permission",
			err:       fs.ErrPermission,
			normalize: transportError,
			code:      failure.CodeTransportPermissionDenied,
		},
		{
			name:      "transport",
			err:       failureCause,
			normalize: transportError,
			code:      failure.CodeTransportFailure,
		},
		{
			name:      "proxy",
			err:       proxyCause,
			normalize: proxyUnavailableError,
			code:      failure.CodeTransportProxyUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.normalize(tt.err)

			if !failure.IsCode(err, tt.code) {
				t.Fatalf("code = %q, want %q", failure.Snapshot(err).Code, tt.code)
			}

			if phase := failure.Snapshot(err).Phase; phase != failure.PhaseDiscovery {
				t.Fatalf("phase = %q, want %q", phase, failure.PhaseDiscovery)
			}

			if !errors.Is(err, tt.err) {
				t.Fatalf("error %v does not preserve cause %v", err, tt.err)
			}
		})
	}
}
