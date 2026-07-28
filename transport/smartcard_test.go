package transport

import (
	"errors"
	"testing"

	ctapiso7816 "github.com/go-ctap/ctap/transport/iso7816"
	baseiso7816 "github.com/go-ctap/iso7816"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/pcsc"
)

func TestSmartCardClassification(t *testing.T) {
	if !isNonFIDOCard(&baseiso7816.APDUError{SW1: 0x6a, SW2: 0x82}) {
		t.Fatal("missing FIDO applet was not classified as a non-FIDO card")
	}
	if !isNonFIDOCard(ctapiso7816.ErrUnsupportedVersion) {
		t.Fatal("unsupported applet version was not classified as a non-FIDO card")
	}
	if isNonFIDOCard(errors.New("reader disconnected")) {
		t.Fatal("reader failure was classified as a non-FIDO card")
	}
}

func TestSmartCardFailureCode(t *testing.T) {
	if got := failureCodeForSmartCard(pcsc.ErrNoAccess); got != failure.CodeTransportPermissionDenied {
		t.Fatalf("permission code = %q, want %q", got, failure.CodeTransportPermissionDenied)
	}
	if got := failureCodeForSmartCard(pcsc.ErrNoService); got != failure.CodeTransportFailure {
		t.Fatalf("transport code = %q, want %q", got, failure.CodeTransportFailure)
	}
}
