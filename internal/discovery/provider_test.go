package discovery

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
		name     string
		err      error
		fallback failure.Code
		code     failure.Code
	}{
		{
			name:     "canceled",
			err:      context.Canceled,
			fallback: failure.CodeTransportFailure,
			code:     failure.CodeOperationCanceled,
		},
		{
			name:     "deadline",
			err:      context.DeadlineExceeded,
			fallback: failure.CodeTransportFailure,
			code:     failure.CodeOperationTimeout,
		},
		{
			name:     "permission",
			err:      fs.ErrPermission,
			fallback: failure.CodeTransportFailure,
			code:     failure.CodeTransportPermissionDenied,
		},
		{
			name:     "transport",
			err:      failureCause,
			fallback: failure.CodeTransportFailure,
			code:     failure.CodeTransportFailure,
		},
		{
			name:     "proxy",
			err:      proxyCause,
			fallback: failure.CodeTransportProxyUnavailable,
			code:     failure.CodeTransportProxyUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := normalizeTransportError(tt.err, tt.fallback)

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
