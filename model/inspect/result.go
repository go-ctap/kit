// Package inspect contains public authenticator inspection results.
package inspect

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/conformance"
	"github.com/go-ctap/kit/model/report"
)

type Info struct {
	protocol.AuthenticatorGetInfoResponse
	UVModalityLabel string             `json:"uvModalityLabel,omitempty"`
	Conformance     conformance.Report `json:"conformance"`
}

type Result struct {
	Device report.DeviceReport `json:"device"`
	Info   Info                `json:"info"`
}

func NewResult(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) Result {
	result := Result{
		Device: device,
		Info: Info{
			AuthenticatorGetInfoResponse: info,
			Conformance:                  conformance.EvaluateGetInfo(info),
		},
	}

	if info.UvModality != nil {
		result.Info.UVModalityLabel = info.UvModality.String()
	}

	return result
}
