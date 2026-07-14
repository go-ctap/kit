package errornorm

import (
	"errors"

	ctapclient "github.com/go-ctap/ctap/client"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	ctaptoken2 "github.com/go-ctap/ctap/transport/token2"
	"github.com/go-ctap/kit/model/failure"
)

func transportCode(err error) (failure.Code, bool) {
	var response *ctaphid.ErrorResponse
	if errors.As(err, &response) {
		return failure.CodeTransportFailure, true
	}

	var ioErr *ctaptransport.IOError
	if errors.As(err, &ioErr) {
		return failure.CodeTransportFailure, true
	}

	var apduErr *ctaptoken2.APDUError
	if errors.As(err, &apduErr) {
		return failure.CodeTransportFailure, true
	}

	if errors.Is(err, ctapclient.ErrTransportNotConfigured) ||
		errors.Is(err, ctaphid.ErrMessageTooLarge) ||
		errors.Is(err, ctaphid.ErrInvalidRequestMessage) ||
		errors.Is(err, ctaphid.ErrUnexpectedCommand) ||
		errors.Is(err, ctaphid.ErrInvalidResponseMessage) ||
		errors.Is(err, ctaptoken2.ErrInvalidResponse) ||
		errors.Is(err, ctaptoken2.ErrCommandTooLarge) {
		return failure.CodeTransportFailure, true
	}

	return "", false
}
