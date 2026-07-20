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
	Assessment      Assessment         `json:"assessment"`
	Conformance     conformance.Report `json:"conformance"`
}

type Result struct {
	Device report.DeviceReport `json:"device"`
	Info   Info                `json:"info"`
}
