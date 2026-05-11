package model

import (
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/kit/model/report"
)

type InspectInfo struct {
	ctaptypes.AuthenticatorGetInfoResponse
	UVModalityLabel string `json:"uvModalityLabel,omitempty"`
}

type InspectResult struct {
	Device report.DeviceReport `json:"device"`
	Info   InspectInfo         `json:"info"`
}

type InspectOutput struct {
	Result InspectResult `json:"result"`
}

func (InspectOutput) ctapkitResult() {}

func NewInspectResult(device report.DeviceReport, info ctaptypes.AuthenticatorGetInfoResponse) InspectResult {
	result := InspectResult{
		Device: device,
		Info: InspectInfo{
			AuthenticatorGetInfoResponse: info,
		},
	}
	if info.UvModality != nil {
		result.Info.UVModalityLabel = info.UvModality.String()
	}

	return result
}
