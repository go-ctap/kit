package model

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/conformance"
	"github.com/go-ctap/kit/model/report"
)

type InspectInfo struct {
	protocol.AuthenticatorGetInfoResponse
	UVModalityLabel string             `json:"uvModalityLabel,omitempty"`
	Conformance     conformance.Report `json:"conformance"`
}

type InspectResult struct {
	Device report.DeviceReport `json:"device"`
	Info   InspectInfo         `json:"info"`
}

type InspectOutput struct {
	Result InspectResult `json:"result"`
}

func (InspectOutput) ctapkitResult() {}

func NewInspectResult(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) InspectResult {
	result := InspectResult{
		Device: device,
		Info: InspectInfo{
			AuthenticatorGetInfoResponse: info,
			Conformance:                  conformance.EvaluateGetInfo(info),
		},
	}
	if info.UvModality != nil {
		result.Info.UVModalityLabel = info.UvModality.String()
	}

	return result
}
