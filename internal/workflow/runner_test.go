package workflow

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/report"
)

type inspectDeviceStub struct {
	info protocol.AuthenticatorGetInfoResponse
}

func (s inspectDeviceStub) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return s.info, true
}

func (s inspectDeviceStub) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return s.info, nil
}

func TestWorkflowEnvironmentContainsOnlySharedServices(t *testing.T) {
	environmentType := reflect.TypeOf(Environment{})
	wantFields := map[string]reflect.Type{
		"Selected":     reflect.TypeOf(report.DeviceReport{}),
		"Events":       reflect.TypeOf((*EventEmitter)(nil)).Elem(),
		"Interactions": reflect.TypeOf((*InteractionRequester)(nil)).Elem(),
		"Tokens":       reflect.TypeOf((*TokenService)(nil)).Elem(),
	}
	if environmentType.NumField() != len(wantFields) {
		t.Fatalf("workflow Environment has %d fields, want %d", environmentType.NumField(), len(wantFields))
	}

	for index := range environmentType.NumField() {
		field := environmentType.Field(index)
		wantType, ok := wantFields[field.Name]
		if !ok {
			t.Fatalf("workflow Environment contains unexpected field %s", field.Name)
		}
		if field.Type != wantType {
			t.Fatalf("workflow Environment field %s has type %s, want %s", field.Name, field.Type, wantType)
		}
	}
}

func TestInspectAcceptsInfoCapabilityOnly(t *testing.T) {
	runner := NewRunner(Environment{
		Selected: report.DeviceReport{Fingerprint: "inspect-capability"},
	})

	result, err := runner.Inspect(t.Context(), inspectDeviceStub{
		info: protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}},
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if result.Device.Fingerprint != "inspect-capability" {
		t.Fatalf("fingerprint = %q, want inspect-capability", result.Device.Fingerprint)
	}
}
